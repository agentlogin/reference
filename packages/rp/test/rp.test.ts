// The relying-party kit against the reference issuer and the agent client, plus ID Token validation against a
// second issuer under the test's control.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { serve } from '@hono/node-server';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { AgentLogin, AgentLoginError, MemoryCookieJar, MemoryKeystore } from 'agentlogin';
import { createIssuer } from '../../issuer/src/index.js';
import { RelyingParty, RelyingPartyError, createHandlers, safeReturnTo, signInForm, type SignIn } from '../src/index.js';

const rnd = (n = 16) => randomBytes(n).toString('base64url');
async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}
const admin = async (base: string, path: string, body: unknown) =>
  (await (await fetch(`${base}${path}`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()) as Record<string, any>;

let issuerUrl = '';
let rpUrl = '';
let rogueUrl = '';
let rp: RelyingParty;
let owner: Record<string, any>;
let rogueKey: { privateKey: CryptoKey; jwk: JWK; kid: string };
const rogueJwks = { cacheControl: undefined as string | undefined, published: true, hits: 0 };
const rogueMeta = { homeIssuers: ['*'] as string[], cacheControl: 'no-store' as string | undefined }; // not cached: each test sees the metadata it sets
const sessions = new Map<string, SignIn>();
const closers: Array<() => Promise<void>> = [];

before(async () => {
  const issuerPort = await freePort();
  issuerUrl = `http://127.0.0.1:${issuerPort}`;
  const { app } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const issuerServer = serve({ fetch: app.fetch, port: issuerPort, hostname: '127.0.0.1' });
  closers.push(() => new Promise((r) => issuerServer.close(() => r())));

  // A second issuer whose signing key the test holds: conforming metadata and JWK Set, tokens minted by the test.
  const roguePort = await freePort();
  rogueUrl = `http://127.0.0.1:${roguePort}`;
  const kp = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(kp.publicKey);
  const jwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
  rogueKey = { privateKey: kp.privateKey, jwk, kid: await calculateJwkThumbprint(jwk, 'sha256') };
  const rogue = http.createServer((req, res) => {
    const send = (v: unknown, headers: Record<string, string> = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(v)); };
    if (req.url === '/.well-known/openid-configuration') {
      send({ issuer: rogueUrl, authorization_endpoint: `${rogueUrl}/authorize`, token_endpoint: `${rogueUrl}/token`, userinfo_endpoint: `${rogueUrl}/userinfo`, jwks_uri: `${rogueUrl}/jwks`, transaction_endpoint: `${rogueUrl}/transactions`, agents_endpoint: `${rogueUrl}/agents`, handle_domains: [], home_issuers: rogueMeta.homeIssuers, agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'] }, rogueMeta.cacheControl ? { 'cache-control': rogueMeta.cacheControl } : {});
    } else if (req.url === '/jwks') {
      rogueJwks.hits += 1;
      send({ keys: rogueJwks.published ? [{ ...jwk, kid: rogueKey.kid, use: 'sig', alg: 'ES256' }] : [] }, rogueJwks.cacheControl ? { 'cache-control': rogueJwks.cacheControl } : {});
    }
    else { res.writeHead(404); res.end(); }
  });
  await new Promise<void>((r) => rogue.listen(roguePort, '127.0.0.1', r));
  closers.push(() => new Promise((r) => rogue.close(() => r())));

  const rpPort = await freePort();
  rpUrl = `http://127.0.0.1:${rpPort}`;
  rp = new RelyingParty({
    clientId: `${rpUrl}/client-metadata.json`,
    redirectUri: `${rpUrl}/auth/agent/callback`,
    issuers: [issuerUrl],
    staticIssuers: { 'example.com': issuerUrl },
    stateSecret: 'test-secret-test-secret-test-secret-1234',
    allowInsecure: true,
  });
  const h = createHandlers(rp, {
    metadata: { clientName: 'Kit Test App', maxSignupsPerOwner: 5 },
    onSignIn: (signIn) => {
      const sid = rnd();
      assert.equal(signIn.owner, undefined, 'an Open Client receives no Owner data');
      sessions.set(sid, signIn);
      return new Response(null, { status: 302, headers: { location: signIn.returnTo ?? '/me', 'set-cookie': `sid=${sid}; Path=/; HttpOnly` } });
    },
  });
  const rpServer = serve({
    port: rpPort,
    hostname: '127.0.0.1',
    fetch: async (req: Request) => {
      const u = new URL(req.url);
      const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.get('cookie') ?? '')?.[1];
      const s = sid ? sessions.get(sid) : undefined;
      if (u.pathname === '/client-metadata.json') return h.metadata(req);
      if (u.pathname === '/auth/agent/login') return h.login(req);
      if (u.pathname === '/auth/agent/callback') return h.callback(req);
      if (u.pathname === '/me' || u.pathname === '/dashboard') return s ? Response.json({ key: s.agent.key, handle: s.agent.handle, owner: s.agent.ownerKey, path: u.pathname }) : Response.json({ error: 'not signed in' }, { status: 401 });
      if (u.pathname === '/recheck') {
        if (!s) return Response.json({ error: 'not signed in' }, { status: 401 });
        try { await rp.recheck(s); return Response.json({ ok: true }); } catch (e) { return Response.json({ error: (e as RelyingPartyError).code }, { status: 401 }); }
      }
      return new Response('not found', { status: 404 });
    },
  });
  closers.push(() => new Promise((r) => rpServer.close(() => r())));
  await new Promise((r) => setTimeout(r, 50));

  owner = await admin(issuerUrl, '/admin/owners', { email: 'jane@example.com', name: 'Jane Doe' });
  await admin(issuerUrl, '/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id, name: 'Scout' });
});
after(async () => { for (const c of closers) await c(); });

const newAgent = () => new AgentLogin({ handle: 'scout@example.com', issuer: issuerUrl, allowInsecure: true, keystore: new MemoryKeystore(), cookies: new MemoryCookieJar() });

test('an agent signs in through the kit, starting at the application (Section 5.8)', async () => {
  const al = newAgent();
  const key = await al.enroll({ credential: owner.credential });
  const result = await al.signInAt(`${rpUrl}/auth/agent/login?return_to=%2Fdashboard`);
  assert.equal(result.client.client_name, 'Kit Test App');
  assert.equal(JSON.stringify(result).includes('code='), false, 'the code-bearing URL must not serialise');
  const followed = await al.follow(result);
  assert.equal(followed.status, 200);
  assert.equal(followed.url, `${rpUrl}/dashboard`);
  const me = JSON.parse(followed.body) as { key: string; handle: string; owner: string; path: string };
  assert.equal(me.handle, 'scout@example.com');
  assert.ok(me.key.startsWith(`${issuerUrl} `) && me.key.split(' ')[1]!.length >= 22);
  assert.ok(me.owner.startsWith(`${issuerUrl} `));

  // Section 9 item 6: the live check passes, then fails once the key is revoked.
  assert.equal((await al.fetch(`${rpUrl}/recheck`)).status, 200);
  await al.revokeKey(owner.credential, key.kid);
  const after = await al.fetch(`${rpUrl}/recheck`);
  assert.equal(after.status, 401);
  assert.equal(((await after.json()) as { error: string }).error, 'revoked');
});

test('a sign-in started without the application cookie cannot be completed', async () => {
  const al = newAgent();
  await al.enroll({ credential: owner.credential });
  // The agent is handed a bare Authentication Request URL produced in someone else's session.
  const other = await fetch(`${rpUrl}/auth/agent/login?handle=scout%40example.com`, { redirect: 'manual' });
  const result = await al.signIn({ authorizationUrl: other.headers.get('location')!, expectedHost: new URL(rpUrl).host });
  const followed = await al.follow(result);
  assert.equal(followed.status, 400);
  assert.match(followed.body, /invalid_state/);
  assert.equal(followed.url.includes('?'), false);
});

test('login refuses an Issuer that is not accepted and an invalid handle', async () => {
  const a = await fetch(`${rpUrl}/auth/agent/login?iss=${encodeURIComponent('https://issuer.invalid')}&login_hint=scout%40example.com`, { redirect: 'manual' });
  assert.equal(a.status, 400);
  assert.match(await a.text(), /does not accept/);
  const b = await fetch(`${rpUrl}/auth/agent/login?handle=not-a-handle`, { redirect: 'manual' });
  assert.equal(b.status, 400);
  for (const hint of ['not-a-handle', 'a%40nonexistent.invalid', 'scout%40example.com']) {
    const r = await fetch(`${rpUrl}/auth/agent/login?iss=${encodeURIComponent('https://unaccepted.example')}&login_hint=${hint}`, { redirect: 'manual' });
    assert.equal(r.status, 400, hint);
  }
  const c = await fetch(`${rpUrl}/auth/agent/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'handle=scout%40example.com' });
  assert.equal(c.status, 302);
  const u = new URL(c.headers.get('location')!);
  assert.equal(u.origin + u.pathname, `${issuerUrl}/authorize`);
  assert.equal(u.searchParams.get('login_hint'), 'scout@example.com');
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(u.searchParams.get('state')!.length >= 22 && u.searchParams.get('nonce')!.length >= 22);
  assert.match(c.headers.get('set-cookie')!, /HttpOnly; SameSite=Lax/);
});

test('the callback validates state and iss before anything else and presents errors distinctly', async () => {
  const start = async () => {
    const r = await fetch(`${rpUrl}/auth/agent/login?handle=scout%40example.com`, { redirect: 'manual' });
    const state = new URL(r.headers.get('location')!).searchParams.get('state')!;
    return { state, cookie: r.headers.get('set-cookie')!.split(';')[0]! };
  };
  const cb = async (query: string, cookie?: string) => {
    const r = await fetch(`${rpUrl}/auth/agent/callback?${query}`, { redirect: 'manual', headers: cookie ? { cookie } : {} });
    return { status: r.status, text: await r.text() };
  };
  const iss = encodeURIComponent(issuerUrl);
  // Each started sign-in gets one callback: a fresh start per case that carries a valid cookie.
  const withFresh = async (query: (state: string) => string) => { const s = await start(); return cb(query(s.state), s.cookie); };
  const s1 = await start();
  assert.match((await cb(`code=x&state=${s1.state}&iss=${iss}`)).text, /invalid_state/, 'no cookie');
  assert.match((await cb(`code=x&state=${rnd()}&iss=${iss}`, s1.cookie)).text, /invalid_state/, 'state of another sign-in');
  assert.match((await cb(`code=x&state=${s1.state}&iss=${iss}`, `${s1.cookie.split('=')[0]}=garbage`)).text, /invalid_state/, 'tampered cookie');
  assert.match((await withFresh((st) => `code=x&state=${st}&iss=${encodeURIComponent('https://evil.example')}`)).text, /issuer_mismatch/);
  assert.match((await withFresh((st) => `code=x&state=${st}`)).text, /issuer_mismatch/, 'missing iss');
  const denied = await withFresh((st) => `error=access_denied&state=${st}&iss=${iss}`);
  const limit = await withFresh((st) => `error=signup_limit_reached&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=${st}&iss=${iss}`);
  assert.equal(denied.status, 400);
  assert.match(denied.text, /cancelled or is not permitted/);
  assert.match(limit.text, /number of agents it accepts/);
  assert.equal(limit.text.includes('<script>'), false);
  const odd = await withFresh((st) => `error=%3Cb%3Eboom&state=${st}&iss=${iss}`);
  assert.match(odd.text, /issuer_error/);
  assert.equal(odd.text.includes('boom'), false, 'an unknown error code from the Issuer is not echoed');
  const s2 = await start();
  const first = await cb(`code=not-a-code&state=${s2.state}&iss=${iss}`, s2.cookie);
  assert.equal(first.status, 502);
  assert.match(first.text, /token_request_failed/);
  assert.match((await cb(`code=not-a-code&state=${s2.state}&iss=${iss}`, s2.cookie)).text, /duplicate_callback/, 'state is consumed');
});

test('ID Token validation (Section 5.7) and the handle binding (Section 2.5)', async () => {
  const nonce = rnd();
  const clientId = `${rpUrl}/client-metadata.json`;
  const mint = (claims: Record<string, unknown>, o: { exp?: number; iat?: number; aud?: string | string[]; iss?: string } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ nonce, actor_type: 'agent', scope: 'openid email', ...claims })
      .setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid, typ: 'JWT' })
      .setIssuer(o.iss ?? rogueUrl).setSubject('b1Ykm9wQ2tN0cJ6vR8dLxA').setAudience(o.aud ?? clientId).setIssuedAt(o.iat ?? now).setExpirationTime(o.exp ?? now + 600).setJti(rnd())
      .sign(rogueKey.privateKey);
  };
  const cfg = { clientId, redirectUri: `${rpUrl}/auth/agent/callback`, staticIssuers: { 'example.com': issuerUrl }, stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true };
  const plain = new RelyingParty({ ...cfg, issuers: [issuerUrl, rogueUrl] });
  const relay = new RelyingParty({ ...cfg, issuers: [{ issuer: rogueUrl, relay: true }] }); // the Relay only: accepting its Home Issuer as well is refused (Section 9 item 10)
  const check = (r: RelyingParty, token: string) => r.validateIdToken(token, { issuer: rogueUrl, nonce, clientId });
  const rejects = (p: Promise<unknown>, code: string) => assert.rejects(p, (e: unknown) => e instanceof RelyingPartyError && e.code === code, code);

  // A valid token without `email` is accepted from a configured Issuer.
  assert.equal((await check(plain, await mint({}))).actor_type, 'agent');
  // A configured Issuer cannot speak for a handle whose domain designates another Issuer.
  await rejects(check(plain, await mint({ email: 'scout@example.com', email_verified: true })), 'handle_binding_failed');
  await rejects(check(plain, await mint({ email: 'scout@example.com' })), 'invalid_id_token');
  // home_iss only from a configured Relay, with or without email (R-14).
  await rejects(check(plain, await mint({ home_iss: issuerUrl })), 'handle_binding_failed');
  await rejects(check(plain, await mint({ home_iss: issuerUrl, email: 'scout@example.com', email_verified: true })), 'handle_binding_failed');
  // A Relay token: discovery for the handle must yield home_iss.
  const viaRelay = await check(relay, await mint({ home_iss: issuerUrl, email: 'scout@example.com', email_verified: true }));
  assert.equal(viaRelay.home_iss, issuerUrl);
  await rejects(check(relay, await mint({ home_iss: 'https://other.example', email: 'scout@example.com', email_verified: true })), 'handle_binding_failed');

  await rejects(check(plain, await mint({ nonce: rnd() })), 'invalid_id_token');
  await rejects(check(plain, await mint({ actor_type: 'user' })), 'invalid_id_token');
  await rejects(check(plain, await mint({ actor_type: undefined })), 'invalid_id_token');
  await rejects(check(plain, await mint({}, { aud: 'someone-else' })), 'invalid_id_token');
  await rejects(check(plain, await mint({}, { aud: [clientId, 'other'] })), 'invalid_id_token');
  await rejects(check(plain, await mint({}, { exp: Math.floor(Date.now() / 1000) - 1, iat: Math.floor(Date.now() / 1000) - 700 })), 'invalid_id_token');
  await rejects(check(plain, await mint({}, { iat: Math.floor(Date.now() / 1000) + 600, exp: Math.floor(Date.now() / 1000) + 1200 })), 'invalid_id_token');
  await rejects(check(plain, await mint({}, { iss: issuerUrl })), 'invalid_id_token');
  const noExp = await new SignJWT({ nonce, actor_type: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('b1Ykm9wQ2tN0cJ6vR8dLxA').setAudience(clientId).setIssuedAt().sign(rogueKey.privateKey);
  await rejects(check(plain, noExp), 'invalid_id_token');
  // Another key, same kid: the signature does not verify.
  const other = await generateKeyPair('ES256');
  const forged = await new SignJWT({ nonce, actor_type: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('x').setAudience(clientId).setIssuedAt().setExpirationTime('5m').sign(other.privateKey);
  await rejects(check(plain, forged), 'invalid_id_token');
  // Unsigned and symmetric tokens are refused before any key lookup.
  const none = `${Buffer.from(JSON.stringify({ alg: 'none', kid: rogueKey.kid })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: rogueUrl, aud: clientId, nonce, actor_type: 'agent', sub: 'x' })).toString('base64url')}.`;
  await rejects(check(plain, none), 'invalid_id_token');
  const hs = await new SignJWT({ nonce, actor_type: 'agent' }).setProtectedHeader({ alg: 'HS256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('x').setAudience(clientId).setExpirationTime('5m').sign(new TextEncoder().encode(JSON.stringify(rogueKey.jwk)));
  await rejects(check(plain, hs), 'invalid_id_token');
});

test('#5 the JWK Set is cached only as long as the Issuer allows; a removed key stops verifying', async () => {
  const nonce = rnd();
  const clientId = `${rpUrl}/client-metadata.json`;
  const mint = () => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ nonce, actor_type: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('b1Ykm9wQ2tN0cJ6vR8dLxA').setAudience(clientId).setIssuedAt(now).setExpirationTime(now + 600).sign(rogueKey.privateKey);
  };
  const fresh = () => new RelyingParty({ clientId, redirectUri: `${rpUrl}/auth/agent/callback`, issuers: [rogueUrl], stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true });
  const check = async (r: RelyingParty) => r.validateIdToken(await mint(), { issuer: rogueUrl, nonce, clientId });
  try {
    for (const cc of ['no-store', 'no-cache', 'max-age=0', 'private, max-age=0']) {
      rogueJwks.cacheControl = cc;
      rogueJwks.published = true;
      const r = fresh();
      const before = rogueJwks.hits;
      await check(r);
      await check(r);
      assert.equal(rogueJwks.hits - before, 2, `${cc}: fetched for every validation`);
      rogueJwks.published = false; // the Issuer removes the key, for example after a compromise
      await assert.rejects(check(r), (e: unknown) => e instanceof RelyingPartyError && e.code === 'invalid_id_token', `${cc}: removed key`);
    }
    // Within a lifetime the Issuer itself allows, the cached set is used (Section 7.7 builds on this).
    rogueJwks.cacheControl = 'max-age=120';
    rogueJwks.published = true;
    const r = fresh();
    const before = rogueJwks.hits;
    await check(r);
    await check(r);
    assert.equal(rogueJwks.hits - before, 1, 'max-age=120: one fetch');
    // An unknown kid triggers one refetch, then is throttled without touching the cache lifetime.
    const other = await generateKeyPair('ES256');
    const unknown = () => new SignJWT({ nonce, actor_type: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: 'unknown-kid' }).setIssuer(rogueUrl).setSubject('x').setAudience(clientId).setIssuedAt().setExpirationTime('5m').sign(other.privateKey);
    const h0 = rogueJwks.hits;
    for (let i = 0; i < 5; i += 1) await assert.rejects(r.validateIdToken(await unknown(), { issuer: rogueUrl, nonce, clientId }));
    assert.equal(rogueJwks.hits - h0, 1, 'unknown kid: one refetch, then throttled');
    await check(r); // the known key still verifies from the cache
  } finally {
    rogueJwks.cacheControl = undefined;
    rogueJwks.published = true;
  }
});

test('#8 the Relay overlap check follows the Relay\'s metadata as it changes', async () => {
  const cfg = { clientId: `${rpUrl}/client-metadata.json`, redirectUri: `${rpUrl}/auth/agent/callback`, stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true, staticIssuers: { 'example.com': issuerUrl } };
  try {
    // The test Relay's metadata is not cacheable, so the kit sees a change at once; otherwise at its next refresh.
    rogueMeta.homeIssuers = ['https://elsewhere.example'];
    const r = new RelyingParty({ ...cfg, issuers: [issuerUrl, { issuer: rogueUrl, relay: true }] });
    assert.ok((await r.begin({ handle: 'scout@example.com' })).url.startsWith(`${issuerUrl}/authorize?`), 'no overlap: the Home Issuer is used directly');
    // The Relay starts relaying an Issuer this application also accepts directly.
    rogueMeta.homeIssuers = ['https://elsewhere.example', issuerUrl];
    await assert.rejects(r.begin({ handle: 'scout@example.com' }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'configuration_error');
    // and a token through the Relay for that Issuer is not accepted either
    const nonce = rnd();
    const now = Math.floor(Date.now() / 1000);
    const viaRelay = await new SignJWT({ nonce, actor_type: 'agent', home_iss: issuerUrl, email: 'scout@example.com', email_verified: true }).setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('b1Ykm9wQ2tN0cJ6vR8dLxA').setAudience(cfg.clientId).setIssuedAt(now).setExpirationTime(now + 600).sign(rogueKey.privateKey);
    await assert.rejects(r.validateIdToken(viaRelay, { issuer: rogueUrl, nonce, clientId: cfg.clientId }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'configuration_error');
    rogueMeta.homeIssuers = ['https://elsewhere.example'];
    assert.ok((await r.begin({ handle: 'scout@example.com' })).url.startsWith(`${issuerUrl}/authorize?`), 'the overlap is gone again');
  } finally {
    rogueMeta.homeIssuers = ['*'];
  }
});

test('#9 Owner data is reported for every owner scope, with or without profile', async () => {
  const nonce = rnd();
  const clientId = 's6BhdRkqt3';
  const r = new RelyingParty({ clientId, redirectUri: `${rpUrl}/auth/agent/callback`, issuers: [rogueUrl], stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true });
  const mint = (claims: Record<string, unknown>) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ nonce, actor_type: 'agent', ...claims }).setProtectedHeader({ alg: 'ES256', kid: rogueKey.kid }).setIssuer(rogueUrl).setSubject('b1Ykm9wQ2tN0cJ6vR8dLxA').setAudience(clientId).setIssuedAt(now).setExpirationTime(now + 600).sign(rogueKey.privateKey);
  };
  const of = async (claims: Record<string, unknown>) => r.identityOf(await r.validateIdToken(await mint(claims), { issuer: rogueUrl, nonce, clientId }));
  // `openid owner_email`: no owner_sub, since that comes with `profile`
  const emailOnly = await of({ scope: 'openid owner_email', owner_email: 'jane@example.com', owner_email_verified: true, owner_verified_via: 'passkey' });
  assert.deepEqual(emailOnly.owner, { key: undefined, name: undefined, email: 'jane@example.com', verifiedVia: 'passkey' });
  assert.equal(emailOnly.agent.ownerKey, undefined);
  const nameOnly = await of({ scope: 'openid owner_profile', owner_name: 'Jane Doe', owner_verified_via: 'email' });
  assert.equal(nameOnly.owner?.name, 'Jane Doe');
  const full = await of({ scope: 'openid profile owner_email', owner_sub: 'oV3nJ8dK1qT6xB2mZ9cL4r', owner_email: 'jane@example.com', owner_email_verified: true, owner_verified_via: 'oidc' });
  assert.equal(full.owner?.key, `${rogueUrl} oV3nJ8dK1qT6xB2mZ9cL4r`);
  assert.equal(full.agent.ownerKey, full.owner?.key);
  // an address the Issuer does not vouch for is not reported as the Owner's
  assert.equal((await of({ scope: 'openid owner_email', owner_email: 'jane@example.com' })).owner?.email, undefined);
  assert.equal((await of({ scope: 'openid profile', owner_sub: 'oV3nJ8dK1qT6xB2mZ9cL4r' })).owner, undefined, 'no Owner data without an owner scope');
});

test('issuer choice: allow-list, relay and open federation', async () => {
  const cfg = { clientId: `${rpUrl}/client-metadata.json`, redirectUri: `${rpUrl}/auth/agent/callback`, stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true };
  const elsewhere = { 'example.com': issuerUrl, 'agents.example': rogueUrl };
  const allow = new RelyingParty({ ...cfg, issuers: [issuerUrl], staticIssuers: elsewhere });
  await assert.rejects(allow.begin({ handle: 'a@agents.example' }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'issuer_not_accepted');
  assert.ok((await allow.begin({ handle: 'scout@example.com' })).url.startsWith(`${issuerUrl}/authorize?`));
  assert.ok((await allow.begin()).url.startsWith(`${issuerUrl}/authorize?`), 'single Issuer needs no handle');
  const any = new RelyingParty({ ...cfg, issuers: [issuerUrl], federation: 'any', staticIssuers: elsewhere });
  assert.ok((await any.begin({ handle: 'a@agents.example' })).url.startsWith(`${rogueUrl}/authorize?`));
  assert.ok((await any.beginInitiated({ iss: rogueUrl, loginHint: 'a@agents.example' })).url.startsWith(`${rogueUrl}/authorize?`));
  await assert.rejects(any.beginInitiated({ iss: rogueUrl, loginHint: 'scout@example.com' }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'issuer_not_accepted');
  await assert.rejects(any.beginInitiated({ iss: rogueUrl }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'issuer_not_accepted');
  const viaRelay = new RelyingParty({ ...cfg, issuers: [{ issuer: rogueUrl, relay: true }], staticIssuers: elsewhere });
  const b = await viaRelay.begin({ handle: 'scout@example.com' });
  assert.ok(b.url.startsWith(`${rogueUrl}/authorize?`) && new URL(b.url).searchParams.get('login_hint') === 'scout@example.com');
  const two = new RelyingParty({ ...cfg, issuers: [issuerUrl, rogueUrl], staticIssuers: elsewhere });
  await assert.rejects(two.begin(), (e: unknown) => e instanceof RelyingPartyError && e.code === 'handle_required');
});

test('configuration rules: secrets stay with their Issuer, one Relay, no Relay beside a Home Issuer it relays', async () => {
  const cfg = { clientId: 's6BhdRkqt3', redirectUri: `${rpUrl}/auth/agent/callback`, stateSecret: 'test-secret-test-secret-test-secret-1234', allowInsecure: true, staticIssuers: { 'example.com': issuerUrl } };
  assert.throws(() => new RelyingParty({ ...cfg, clientSecret: 'x', issuers: [issuerUrl, rogueUrl] }), /clientSecret/);
  assert.throws(() => new RelyingParty({ ...cfg, clientSecret: 'x', issuers: [issuerUrl], federation: 'any' }), /clientSecret/);
  assert.throws(() => new RelyingParty({ ...cfg, issuers: [{ issuer: rogueUrl, relay: true }, { issuer: issuerUrl, relay: true }] }), /one Relay/);
  assert.throws(() => new RelyingParty({ ...cfg, issuers: [{ issuer: rogueUrl, relay: true }], federation: 'any' }), /Relay/);
  assert.throws(() => new RelyingParty({ ...cfg, issuers: ['not a url'] }), /Issuer Identifier/);
  assert.throws(() => new RelyingParty({ ...cfg, issuers: [issuerUrl], stateSecret: undefined as unknown as string }), /stateSecret/);
  // the test Relay accepts every Home Issuer ("*"), so listing one beside it is a configuration error
  const both = new RelyingParty({ ...cfg, issuers: [issuerUrl, { issuer: rogueUrl, relay: true }] });
  await assert.rejects(both.begin({ handle: 'scout@example.com' }), (e: unknown) => e instanceof RelyingPartyError && e.code === 'configuration_error' && e.status === 500);
});

test('return_to accepts same-origin paths only', () => {
  for (const ok of ['/', '/dashboard', '/a/b?c=d&e=f#g']) assert.equal(safeReturnTo(ok), ok);
  for (const bad of ['//evil.example', '/\\evil.example', '/\t/evil.example', '/\n/evil.example', 'https://evil.example', 'javascript:alert(1)', '/ space', '', `/${'a'.repeat(600)}`]) {
    assert.equal(safeReturnTo(bad), undefined, JSON.stringify(bad));
  }
});

test('the sign-in form escapes its inputs', () => {
  const html = signInForm({ action: '/auth/agent/login?x="><script>', label: '<b>Sign in</b>', returnTo: '/a"b' });
  assert.equal(html.includes('<script>'), false);
  assert.equal(html.includes('<b>'), false);
  assert.match(html, /name="handle"/);
  assert.equal(signInForm({ action: '/l', withoutHandle: true }).includes('name="handle"'), false);
  void AgentLoginError;
});
