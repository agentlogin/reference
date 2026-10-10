// End to end: a stub Relying Party (Open Client) + the reference issuer + this client library.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createIssuer } from '../../issuer/src/index.js';
import { AgentLogin, AgentLoginError, MemoryCookieJar, MemoryKeystore } from '../src/index.js';

const b64u = (n = 16) => randomBytes(n).toString('base64url');
async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}
async function post(url: string, token: string, body: unknown) {
  const r = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return r.json() as Promise<Record<string, any>>;
}

test('agent signs in to a relying party end to end', async () => {
  const issuerPort = await freePort();
  const issuerUrl = `http://127.0.0.1:${issuerPort}`;
  const { app, ctx } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const issuerServer = serve({ fetch: app.fetch, port: issuerPort, hostname: '127.0.0.1' });

  // --- stub Relying Party: Open Client with metadata document, /login, /cb, /me ---
  const sessions = new Map<string, { sub: string; email: string }>();
  const pending = new Map<string, { verifier: string; nonce: string }>();
  const jwks = createRemoteJWKSet(new URL(`${issuerUrl}/.well-known/jwks.json`));
  let rpUrl = '';
  const rp = http.createServer(async (req, res) => {
    const u = new URL(req.url!, rpUrl);
    if (u.pathname === '/client-metadata.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ client_id: `${rpUrl}/client-metadata.json`, redirect_uris: [`${rpUrl}/cb`], token_endpoint_auth_method: 'none', client_name: 'Example App' }));
    } else if (u.pathname === '/login') {
      const verifier = b64u(32);
      const state = b64u();
      const nonce = b64u();
      pending.set(state, { verifier, nonce });
      const a = new URL(`${issuerUrl}/authorize`);
      a.search = new URLSearchParams({ response_type: 'code', client_id: `${rpUrl}/client-metadata.json`, redirect_uri: `${rpUrl}/cb`, scope: 'openid email profile', state, nonce, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
      res.writeHead(302, { location: a.href });
      res.end();
    } else if (u.pathname === '/cb') {
      const p = pending.get(u.searchParams.get('state') ?? '');
      if (!p || u.searchParams.get('iss') !== issuerUrl) { res.writeHead(400); res.end('bad state'); return; }
      const tr = await fetch(`${issuerUrl}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: u.searchParams.get('code')!, redirect_uri: `${rpUrl}/cb`, client_id: `${rpUrl}/client-metadata.json`, code_verifier: p.verifier }) });
      const tok = (await tr.json()) as { id_token: string };
      const { payload } = await jwtVerify(tok.id_token, jwks, { issuer: issuerUrl, audience: `${rpUrl}/client-metadata.json` });
      if (payload.nonce !== p.nonce || payload.actor_type !== 'agent') { res.writeHead(400); res.end('bad token'); return; }
      const sid = b64u();
      sessions.set(sid, { sub: payload.sub!, email: payload.email as string });
      res.writeHead(302, { 'set-cookie': `rp_session=${sid}; Path=/; HttpOnly`, location: '/me' });
      res.end();
    } else if (u.pathname === '/me') {
      const sid = /rp_session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
      const s = sid && sessions.get(sid);
      res.writeHead(s ? 200 : 401, { 'content-type': 'application/json' });
      res.end(JSON.stringify(s ?? { error: 'not signed in' }));
    } else { res.writeHead(404); res.end(); }
  });
  await new Promise<void>((r) => rp.listen(0, '127.0.0.1', r));
  rpUrl = `http://127.0.0.1:${(rp.address() as AddressInfo).port}`;

  try {
    const owner = await post(`${issuerUrl}/admin/owners`, 'admin', { email: 'jane@example.com', name: 'Jane Doe' });
    await post(`${issuerUrl}/admin/agents`, 'admin', { handle: 'scout@example.com', owner_id: owner.owner_id, name: 'Scout' });

    const al = new AgentLogin({ handle: 'scout@example.com', issuer: issuerUrl, allowInsecure: true, keystore: new MemoryKeystore(), cookies: new MemoryCookieJar() });
    const key = await al.enroll({ credential: owner.credential, name: 'test' });
    assert.equal(key.status, 'active');

    // The agent visits the RP's login link and takes the Authentication Request URL it is sent to.
    const login = await fetch(`${rpUrl}/login`, { redirect: 'manual' });
    const authorizationUrl = login.headers.get('location')!;
    assert.ok(authorizationUrl.startsWith(`${issuerUrl}/authorize?`));

    // Wrong expected host is refused before any assertion is made (A-3).
    await assert.rejects(al.signIn({ authorizationUrl, expectedHost: 'attacker.example' }), (e: unknown) => e instanceof AgentLoginError && e.code === 'unexpected_client');

    const login2 = await fetch(`${rpUrl}/login`, { redirect: 'manual' });
    const result = await al.signIn({ authorizationUrl: login2.headers.get('location')!, expectedHost: new URL(rpUrl).host });
    assert.equal(result.client.client_name, 'Example App');
    const followed = await al.follow(result);
    assert.equal(followed.status, 200);
    const me = (await (await al.fetch(`${rpUrl}/me`)).json()) as { email: string; sub: string };
    assert.equal(me.email, 'scout@example.com');

    // Second sign-in: the Consent Record makes the review unnecessary and the sub is stable.
    const login3 = await fetch(`${rpUrl}/login`, { redirect: 'manual' });
    let reviewed = false;
    const r3 = await al.signIn({ authorizationUrl: login3.headers.get('location')!, expectedHost: new URL(rpUrl).host, onReview: () => { reviewed = true; return 'allow'; } });
    assert.equal(reviewed, false);
    const f3 = await al.follow(r3);
    assert.equal(f3.status, 200);
    const me2 = (await (await al.fetch(`${rpUrl}/me`)).json()) as { sub: string };
    assert.equal(me2.sub, me.sub);

    // Revocation: a revoked key cannot sign in again; a fresh enrollment can.
    await al.revokeKey(owner.credential, key.kid);
    const login4 = await fetch(`${rpUrl}/login`, { redirect: 'manual' });
    await assert.rejects(al.signIn({ authorizationUrl: login4.headers.get('location')!, expectedHost: new URL(rpUrl).host }), (e: unknown) => e instanceof AgentLoginError && e.code === 'no_key');
    await al.enroll({ credential: owner.credential, name: 'second' });
    const login5 = await fetch(`${rpUrl}/login`, { redirect: 'manual' });
    const r5 = await al.signIn({ authorizationUrl: login5.headers.get('location')!, expectedHost: new URL(rpUrl).host });
    assert.equal((await al.follow(r5)).status, 200);
    void ctx;
  } finally {
    await new Promise<void>((r) => issuerServer.close(() => r()));
    await new Promise<void>((r) => rp.close(() => r()));
  }
});
