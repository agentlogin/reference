// Regression tests for defects reported against commit 9b6dd09. Each drives the issuer in process through
// app.request, with an injectable clock, so that races and lifetimes are exercised directly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, decodeJwt, type CryptoKey, type JWK } from 'jose';
import { createIssuer } from '../src/index.js';

const ISS = 'https://issuer.test';
const rnd = (n = 16) => randomBytes(n).toString('base64url');

async function world(opts: { name?: string | null; constants?: Record<string, number> } = {}) {
  let clock = Math.floor(Date.now() / 1000);
  const { app, ctx } = await createIssuer({ issuer: ISS, handleDomains: ['example.com'], adminToken: 'admin', now: () => clock, constants: opts.constants });
  const req = async (method: string, path: string, o: { json?: unknown; form?: Record<string, string>; headers?: Record<string, string> } = {}) => {
    const headers: Record<string, string> = { accept: 'application/json', ...o.headers };
    let body: string | undefined;
    if (o.json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(o.json); }
    if (o.form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(o.form).toString(); }
    const r = await app.request(path.startsWith('http') ? path : `${ISS}${path}`, { method, headers, body });
    const text = await r.text();
    let json: any;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    return { status: r.status, json, text, headers: r.headers };
  };
  const admin = { authorization: 'Bearer admin' };
  const ownerBody: Record<string, unknown> = { email: `owner-${rnd(4)}@example.org`, session_auth: 'passkey' };
  if (opts.name !== null) ownerBody.name = opts.name ?? 'Jane Doe';
  const owner = (await req('POST', '/admin/owners', { json: ownerBody, headers: admin })).json as { owner_id: string; credential: string };
  const cred = { authorization: `Bearer ${owner.credential}` };

  async function agent(handle: string, shareOwner = false) {
    const created = await req('POST', '/admin/agents', { json: { handle, owner_id: owner.owner_id, name: 'Test agent' }, headers: admin });
    assert.equal(created.status, 201, created.text);
    const kp = await generateKeyPair('ES256', { extractable: true });
    const pub = await exportJWK(kp.publicKey);
    const jwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
    const kid = await calculateJwkThumbprint(jwk, 'sha256');
    const base = `/agents/${encodeURIComponent(handle)}/keys`;
    const en = await req('POST', base, { json: { jwk }, headers: cred });
    assert.equal(en.status, 201, en.text);
    const proof = await sign(kp.privateKey, kid, handle, 'agent-login-enrollment+jwt', { nonce: en.json.challenge });
    assert.equal((await req('POST', en.json.proof_url, { json: { proof } })).status, 200);
    if (shareOwner) assert.equal((await req('PATCH', `${base}/${kid}`, { json: { permissions: { share_owner: true } }, headers: cred })).status, 200);
    return { handle, kid, privateKey: kp.privateKey };
  }
  async function sign(privateKey: CryptoKey, kid: string, handle: string, typ: string, claims: Record<string, unknown>) {
    return new SignJWT({ jti: rnd(), ...claims }).setProtectedHeader({ alg: 'ES256', typ, kid }).setIssuer(handle).setSubject(handle).setAudience(ISS).setIssuedAt(clock).setExpirationTime(clock + 60).sign(privateKey);
  }
  async function client(meta: Record<string, unknown> = {}) {
    const redirect_uri = `https://rp-${rnd(4).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.example/cb`;
    const r = await req('POST', '/register', { json: { redirect_uris: [redirect_uri], client_name: 'Test', tos_uri: 'https://rp.example/tos', policy_uri: 'https://rp.example/privacy', token_endpoint_auth_method: 'client_secret_basic', ...meta }, headers: admin });
    assert.equal(r.status, 201, r.text);
    return { client_id: r.json.client_id as string, client_secret: r.json.client_secret as string, redirect_uri };
  }
  type C = Awaited<ReturnType<typeof client>>;
  type A = Awaited<ReturnType<typeof agent>>;
  async function start(c: C, over: Record<string, string> = {}) {
    const verifier = rnd(32);
    const q = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: c.redirect_uri, scope: 'openid email profile', state: rnd(), nonce: rnd(), code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', ...over });
    const r = await req('GET', `/authorize?${q}`);
    assert.equal(r.status, 200, r.text);
    return { tx: r.json, verifier };
  }
  async function assertOn(tx: any, a: A, extra: Record<string, unknown> = {}) {
    const assertion = await sign(a.privateKey, a.kid, a.handle, 'agent-login+jwt', { txn: tx.transaction_id, nonce: tx.challenge, ...extra });
    return req('POST', tx.next.url, { json: { assertion } });
  }
  const cont = (tx: any) => req('GET', tx.next.url, { headers: { authorization: `Bearer ${tx.transaction_token}` } });
  const basic = (c: C) => ({ authorization: `Basic ${Buffer.from(`${c.client_id}:${c.client_secret}`).toString('base64')}` });
  const token = (c: C, code: string, verifier: string) => req('POST', '/token', { form: { grant_type: 'authorization_code', code, redirect_uri: c.redirect_uri, code_verifier: verifier }, headers: basic(c) });
  /** Start, assert with accept_disclosure and return the code. */
  async function signIn(c: C, a: A, over: Record<string, string> = {}, extra: Record<string, unknown> = { accept_disclosure: true }) {
    const s = await start(c, over);
    const asserted = (await assertOn(s.tx, a, extra)).json;
    assert.equal(asserted.status, 'ready', JSON.stringify(asserted).slice(0, 300));
    const redirect = new URL((await cont(asserted)).json.redirect);
    return { code: redirect.searchParams.get('code')!, verifier: s.verifier, tx: asserted };
  }
  return { app, ctx, req, admin, cred, owner, agent, client, start, assertOn, cont, token, signIn, advance: (s: number) => { clock += s; } };
}

test('#1 an authorization code is redeemed once under concurrent Token Requests', async () => {
  const w = await world();
  const a = await w.agent('scout@example.com');
  const c = await w.client();
  const { code, verifier } = await w.signIn(c, a);
  const results = await Promise.all([w.token(c, code, verifier), w.token(c, code, verifier), w.token(c, code, verifier)]);
  const ok = results.filter((r) => r.status === 200);
  assert.equal(ok.length, 1, `statuses ${results.map((r) => r.status).join(',')}`);
  for (const r of results.filter((x) => x.status !== 200)) assert.equal(r.json.error, 'invalid_grant');
  // Section 5.4: the token issued for a code that was presented again is revoked.
  assert.equal((await w.req('GET', '/userinfo', { headers: { authorization: `Bearer ${ok[0]!.json.access_token}` } })).status, 401);
});

test('#2 prompt=consent and require_review force the review even on a first visit with accept_disclosure', async () => {
  const w = await world();
  const a = await w.agent('scout@example.com');
  const c = await w.client();
  const forced = (await w.assertOn((await w.start(c, { prompt: 'consent' })).tx, a, { accept_disclosure: true })).json;
  assert.equal(forced.status, 'awaiting_consent');
  assert.equal(forced.consent_reason, 'prompt_consent');
  const strict = await w.client({ require_review: true });
  const policy = (await w.assertOn((await w.start(strict)).tx, a, { accept_disclosure: true })).json;
  assert.equal(policy.status, 'awaiting_consent');
  assert.equal(policy.consent_reason, 'policy');
  // prompt=none cannot satisfy a forced review
  const none = (await w.assertOn((await w.start(strict, { prompt: 'none' })).tx, a, { accept_disclosure: true })).json;
  assert.equal(none.status, 'denied');
  assert.equal(none.reason, 'consent_required');
  // the review itself completes the sign-in and records the consent
  const allowed = await w.req('POST', policy.next.url, { json: { decision: 'allow' }, headers: { authorization: `Bearer ${policy.transaction_token}` } });
  assert.equal(allowed.json.status, 'ready');
  // without a forcing reason, accept_disclosure still covers a first visit
  const b = await w.agent('rover@example.com');
  assert.equal((await w.assertOn((await w.start(c)).tx, b, { accept_disclosure: true })).json.status, 'ready');
  assert.equal((await w.assertOn((await w.start(c)).tx, await w.agent('probe@example.com'))).json.consent_reason, 'first_visit');
});

test('#6 an expired, abandoned transaction frees its place under the per-owner cap', async () => {
  const w = await world();
  const a1 = await w.agent('one@example.com');
  const a2 = await w.agent('two@example.com');
  const c = await w.client({ max_signups_per_owner: 1 });
  const abandoned = (await w.assertOn((await w.start(c)).tx, a1, { accept_disclosure: true })).json;
  assert.equal(abandoned.status, 'ready');
  const blocked = (await w.assertOn((await w.start(c)).tx, a2, { accept_disclosure: true })).json;
  assert.equal(blocked.reason, 'signup_limit_reached', 'in flight: the place is taken');
  w.advance(301); // T_TXN passed; nobody reads the abandoned transaction
  const after = (await w.assertOn((await w.start(c)).tx, a2, { accept_disclosure: true })).json;
  assert.equal(after.status, 'ready', `after expiry: ${after.status} ${after.reason ?? ''}`);
});

test('#6 concurrent first completions of one Agent count one sign-up', async () => {
  const w = await world();
  const a = await w.agent('scout@example.com');
  const c = await w.client({ max_signups_per_owner: 5 });
  const txs = [];
  for (let i = 0; i < 4; i += 1) txs.push((await w.assertOn((await w.start(c)).tx, a, { accept_disclosure: true })).json);
  for (const t of txs) assert.equal(t.status, 'ready');
  const done = await Promise.all(txs.map((t) => w.cont(t)));
  for (const d of done) assert.equal(d.status, 200);
  assert.equal(await w.ctx.store.signupsEver(w.owner.owner_id, c.client_id), 1);
  const account = await w.ctx.store.getAccount(a.handle, c.client_id);
  assert.equal(account?.signInCount, 4);
});

test('#7 a Consent Record in use does not expire as if idle', async () => {
  const w = await world({ constants: { T_CONSENT: 1000 } }); // a shortened lifetime, in seconds
  const a = await w.agent('scout@example.com');
  const c = await w.client();
  await w.signIn(c, a);
  w.advance(600);
  await w.signIn(c, a, {}, {}); // relies on the record, no accept_disclosure
  w.advance(600); // 1200 s after the acceptance, 600 s after the last use
  const again = (await w.assertOn((await w.start(c)).tx, a)).json;
  assert.equal(again.status, 'ready', `${again.status} ${again.consent_reason ?? ''}`);
  w.advance(1001); // now idle for longer than T_CONSENT
  const idle = (await w.assertOn((await w.start(c)).tx, a)).json;
  assert.equal(idle.status, 'awaiting_consent');
  assert.equal(idle.consent_reason, 'expired');
});

test('#8 handles with characters outside the acct userpart: WebFinger and management routes', async () => {
  const w = await world();
  for (const handle of ['qa#bot@example.com', 'agent%test@example.com', 'a/b?c@example.com', "o'neil+x@example.com"]) {
    const a = await w.agent(handle);
    const [local, domain] = [handle.slice(0, handle.lastIndexOf('@')), handle.slice(handle.lastIndexOf('@') + 1)];
    // RFC 7565 Section 7: the userpart is percent-encoded in the URI, and the URI again as a query value.
    const userpart = [...local].map((ch) => (/[A-Za-z0-9\-._~!$&'()*+,;=]/.test(ch) ? ch : `%${ch.charCodeAt(0).toString(16).toUpperCase()}`)).join('');
    const uri = `acct:${userpart}@${domain}`;
    const wf = await w.req('GET', `/.well-known/webfinger?resource=${encodeURIComponent(uri)}&rel=${encodeURIComponent('http://openid.net/specs/connect/1.0/issuer')}`);
    assert.equal(wf.status, 200, `${handle}: webfinger ${wf.status}`);
    assert.equal(wf.json.subject, uri);
    assert.equal(wf.json.links[0].href, ISS);
    const keys = await w.req('GET', `/agents/${encodeURIComponent(handle)}/keys`, { headers: w.cred });
    assert.equal(keys.status, 200, `${handle}: list keys ${keys.status}`);
    assert.equal(keys.json.keys[0].kid, a.kid);
    assert.equal((await w.req('GET', `/agents/${encodeURIComponent(handle)}/keys/${encodeURIComponent(a.kid)}`, { headers: w.cred })).status, 200);
  }
  // a client identifier that contains a percent sign survives the account and consent routes
  assert.equal((await w.req('DELETE', `/agents/${encodeURIComponent('qa#bot@example.com')}/consents/${encodeURIComponent('https://rp.example/a%20b/client.json')}`, { headers: w.cred })).status, 204);
  assert.equal((await w.req('GET', `/.well-known/webfinger?resource=${encodeURIComponent('acct:%zz@example.com')}`)).status, 404, 'malformed percent-encoding');
  assert.equal((await w.req('GET', `/agents/%E0%A4%A/keys`, { headers: w.cred })).status, 404, 'malformed route parameter');
});

test('#9 a requested Owner Claim that the Issuer cannot supply ends the sign-in instead of being omitted', async () => {
  const w = await world({ name: null }); // an Owner without a display name
  const a = await w.agent('scout@example.com', true);
  const c = await w.client();
  const denied = (await w.assertOn((await w.start(c, { scope: 'openid email owner_profile' })).tx, a, { accept_disclosure: true })).json;
  assert.equal(denied.status, 'denied', `status ${denied.status}`);
  assert.equal(denied.reason, 'access_denied');
  // owner_email alone is satisfiable for this Owner
  const { code, verifier } = await w.signIn(c, a, { scope: 'openid email owner_email' });
  const claims = decodeJwt((await w.token(c, code, verifier)).json.id_token);
  assert.equal(typeof claims.owner_email, 'string');
  assert.equal(claims.owner_email_verified, true);
  const named = await world();
  const b = await named.agent('scout@example.com', true);
  const c2 = await named.client();
  const ok = await named.signIn(c2, b, { scope: 'openid email owner_profile' });
  assert.equal(decodeJwt((await named.token(c2, ok.code, ok.verifier)).json.id_token).owner_name, 'Jane Doe');
});
