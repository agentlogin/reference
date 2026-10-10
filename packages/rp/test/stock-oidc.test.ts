// Interoperability: a stock OpenID Connect library (openid-client 6) as the Relying Party against the reference
// issuer, with no Agent Login code on the Relying Party side. Guards the claim that the profile is plain OIDC
// for the Relying Party (Section 1.4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import * as oidc from 'openid-client';
import { AgentLogin, MemoryCookieJar, MemoryKeystore } from 'agentlogin';
import { createIssuer } from '../../issuer/src/index.js';

test('openid-client completes an Agent Login sign-in unmodified', async () => {
  const probe = http.createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const issuerPort = (probe.address() as AddressInfo).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const issuerUrl = `http://127.0.0.1:${issuerPort}`;
  const { app } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const issuerServer = serve({ fetch: app.fetch, port: issuerPort, hostname: '127.0.0.1' });

  let clientId = '';
  let redirectUri = '';
  const rp = http.createServer((req, res) => {
    if (req.url === '/client-metadata.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ client_id: clientId, redirect_uris: [redirectUri], token_endpoint_auth_method: 'none', client_name: 'Stock OIDC app' }));
    } else { res.writeHead(404); res.end(); }
  });
  await new Promise<void>((r) => rp.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(rp.address() as AddressInfo).port}`;
  clientId = `${base}/client-metadata.json`;
  redirectUri = `${base}/cb`;
  const admin = async (path: string, body: unknown) =>
    (await (await fetch(`${issuerUrl}${path}`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()) as Record<string, string>;

  try {
    // The Relying Party: discovery, PKCE, state, nonce, code exchange, ID Token validation, all by the library.
    const config = await oidc.discovery(new URL(issuerUrl), clientId, undefined, oidc.None(), { execute: [oidc.allowInsecureRequests] });
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const authUrl = oidc.buildAuthorizationUrl(config, { redirect_uri: redirectUri, scope: 'openid email profile', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', state, nonce });

    const owner = await admin('/admin/owners', { email: 'jane@example.com' });
    await admin('/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id!, name: 'Scout' });
    const al = new AgentLogin({ handle: 'scout@example.com', issuer: issuerUrl, allowInsecure: true, keystore: new MemoryKeystore(), cookies: new MemoryCookieJar() });
    await al.enroll({ credential: owner.credential! });
    const result = await al.signIn({ authorizationUrl: authUrl.href, expectedHost: new URL(base).host });

    const tokens = await oidc.authorizationCodeGrant(config, new URL(result.redirectUrl), { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
    const claims = tokens.claims()!;
    assert.equal(claims.iss, issuerUrl);
    assert.equal(claims.actor_type, 'agent');
    assert.equal(claims.email, 'scout@example.com');
    assert.equal(tokens.refresh_token, undefined);
    const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
    assert.equal(userinfo.sub, claims.sub);
  } finally {
    await new Promise<void>((r) => issuerServer.close(() => r()));
    await new Promise<void>((r) => rp.close(() => r()));
  }
});
