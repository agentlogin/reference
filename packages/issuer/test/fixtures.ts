import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { createIssuer, loadSigningKey, MemoryStore, type Store } from '../src/index.js';
import { snapshotting } from './stores.js';

const ISS = 'https://issuer.test';
const rnd = (n = 16) => randomBytes(n).toString('base64url');

/** One or more issuer instances over one store, with an injectable clock. */
export async function world(opts: { store?: Store; stores?: Store[]; instances?: number; insecureClients?: boolean } = {}) {
  let clock = Math.floor(Date.now() / 1000);
  const store = opts.store ?? snapshotting(new MemoryStore());
  const signingJwk = await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey);
  void loadSigningKey;
  const apps = [];
  for (let i = 0; i < (opts.instances ?? 1); i += 1) {
    apps.push((await createIssuer({ issuer: ISS, handleDomains: ['example.com'], adminToken: 'admin', now: () => clock, store: opts.stores?.[i] ?? store, signingJwk, allowInsecureClients: opts.insecureClients })).app);
  }
  const on = (instance: number) => async (method: string, path: string, o: { json?: unknown; form?: Record<string, string>; headers?: Record<string, string> } = {}) => {
    const headers: Record<string, string> = { accept: 'application/json', ...o.headers };
    let body: string | undefined;
    if (o.json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(o.json); }
    if (o.form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(o.form).toString(); }
    const r = await apps[instance]!.request(path.startsWith('http') ? path : `${ISS}${path}`, { method, headers, body });
    const text = await r.text();
    let json: any;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    return { status: r.status, json, text };
  };
  const req = on(0);
  const admin = { authorization: 'Bearer admin' };
  const owner = (await req('POST', '/admin/owners', { json: { email: `owner-${rnd(4)}@example.org`, name: 'Jane Doe', session_auth: 'passkey' }, headers: admin })).json as { owner_id: string; credential: string };
  const cred = { authorization: `Bearer ${owner.credential}` };
  const sign = (privateKey: CryptoKey, kid: string, handle: string, typ: string, claims: Record<string, unknown>) =>
    new SignJWT({ jti: rnd(), ...claims }).setProtectedHeader({ alg: 'ES256', typ, kid }).setIssuer(handle).setSubject(handle).setAudience(ISS).setIssuedAt(clock).setExpirationTime(clock + 60).sign(privateKey);

  async function newKey() {
    const kp = await generateKeyPair('ES256', { extractable: true });
    const pub = await exportJWK(kp.publicKey);
    const jwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
    return { privateKey: kp.privateKey, jwk, kid: await calculateJwkThumbprint(jwk, 'sha256') };
  }
  /** Enrolls `key` for `handle`; returns the pending record and the request that proves it. */
  async function enroll(handle: string, key: Awaited<ReturnType<typeof newKey>>, expiresIn?: number) {
    const en = await req('POST', `/agents/${encodeURIComponent(handle)}/keys`, { json: { jwk: key.jwk, ...(expiresIn ? { expires_at: clock + expiresIn } : {}) }, headers: cred });
    const prove = async () => req('POST', en.json.proof_url, { json: { proof: await sign(key.privateKey, key.kid, handle, 'agent-login-enrollment+jwt', { nonce: en.json.challenge }) } });
    return { en, prove };
  }
  async function agent(handle: string, expiresIn?: number) {
    assert.equal((await req('POST', '/admin/agents', { json: { handle, owner_id: owner.owner_id, name: 'Test agent' }, headers: admin })).status, 201);
    const key = await newKey();
    const { en, prove } = await enroll(handle, key, expiresIn);
    assert.equal(en.status, 201, en.text);
    assert.equal((await prove()).status, 200);
    return { handle, ...key };
  }
  type A = Awaited<ReturnType<typeof agent>>;
  async function client(meta: Record<string, unknown> = {}) {
    const redirect_uri = `https://rp-${rnd(4).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.example/cb`;
    const r = await req('POST', '/register', { json: { redirect_uris: [redirect_uri], client_name: 'Test', tos_uri: 'https://rp.example/tos', policy_uri: 'https://rp.example/privacy', token_endpoint_auth_method: 'client_secret_basic', ...meta }, headers: admin });
    assert.equal(r.status, 201, r.text);
    return { client_id: r.json.client_id as string, client_secret: r.json.client_secret as string, redirect_uri };
  }
  type C = Awaited<ReturnType<typeof client>>;
  async function start(c: C, over: Record<string, string> = {}) {
    const verifier = rnd(32);
    const q = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: c.redirect_uri, scope: 'openid email profile', state: rnd(), nonce: rnd(), code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', ...over });
    const r = await req('GET', `/authorize?${q}`);
    assert.equal(r.status, 200, r.text);
    return { tx: r.json, verifier };
  }
  const assertion = (tx: any, a: A, extra: Record<string, unknown> = { accept_disclosure: true }) => sign(a.privateKey, a.kid, a.handle, 'agent-login+jwt', { txn: tx.transaction_id, nonce: tx.challenge, ...extra });
  const assertOn = async (tx: any, a: A, instance = 0, extra?: Record<string, unknown>) => on(instance)('POST', tx.next.url, { json: { assertion: await assertion(tx, a, extra) } });
  const cont = (tx: any, instance = 0) => on(instance)('GET', tx.next.url, { headers: { authorization: `Bearer ${tx.transaction_token}` } });
  const basic = (c: C) => ({ authorization: `Basic ${Buffer.from(`${c.client_id}:${c.client_secret}`).toString('base64')}` });
  const token = (c: C, code: string, verifier: string, instance = 0) => on(instance)('POST', '/token', { form: { grant_type: 'authorization_code', code, redirect_uri: c.redirect_uri, code_verifier: verifier }, headers: basic(c) });
  /** A sign-in up to `ready`. */
  async function ready(c: C, a: A) {
    const s = await start(c);
    const r = (await assertOn(s.tx, a)).json;
    assert.equal(r.status, 'ready', JSON.stringify(r).slice(0, 200));
    return { tx: r, verifier: s.verifier };
  }
  /** A sign-in up to the code. */
  async function codeFor(c: C, a: A) {
    const r = await ready(c, a);
    return { code: new URL((await cont(r.tx)).json.redirect).searchParams.get('code')!, verifier: r.verifier };
  }
  const revoke = (a: { handle: string; kid: string }) => req('DELETE', `/agents/${encodeURIComponent(a.handle)}/keys/${encodeURIComponent(a.kid)}`, { headers: cred });
  const userinfo = (accessToken: string) => req('GET', '/userinfo', { headers: { authorization: `Bearer ${accessToken}` } });
  return { req, on, admin, cred, owner, store, newKey, enroll, agent, client, start, assertOn, cont, token, ready, codeFor, revoke, userinfo, advance: (s: number) => { clock += s; } };
}

