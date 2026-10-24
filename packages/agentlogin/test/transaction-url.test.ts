import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPair, exportJWK } from 'jose';
import { AgentLogin, AgentLoginError, MemoryKeystore } from '../src/index.js';

for (const mode of ['query', 'descendant', 'sibling', 'outside', 'fragment', 'userinfo', 'foreign', 'none', 'none-ready', 'none-review'] as const) {
  test(`Agent Client checks transaction URL boundary before sending a credential: ${mode}`, async () => {
    let issuer = '';
    const credentialRequests: string[] = [];
    const server = http.createServer((req, res) => {
      const url = new URL(req.url!, issuer);
      if (req.headers.authorization) credentialRequests.push(req.url!);
      res.setHeader('content-type', 'application/json');
      if (url.pathname === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer,
        authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`, transaction_endpoint: `${issuer}/transactions`, agents_endpoint: `${issuer}/agents`,
        handle_domains: ['example.com'], agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'] }));
      const tx = { transaction_id: 'one', iss: issuer, url: `${issuer}/transactions/one`, expires_at: Date.now() / 1000 + 60,
        client: { client_id: 'rp', client_type: 'registered', redirect_host: 'rp.example' }, requested_scopes: ['openid'], disclosure: [] };
      if (url.pathname === '/authorize') return res.end(JSON.stringify({ ...tx, status: 'awaiting_agent', challenge: 'challenge', session_token: 'session',
        next: { action: 'assert', method: 'POST', url: `${issuer}/transactions/one/assert` } }));
      if (url.pathname.endsWith('/assert')) {
        const target = {
          query: `${issuer}/transactions?ticket=secret`, descendant: `${issuer}/transactions/one/go?version=2`,
          sibling: `${issuer}/transactions-other/go`, outside: `${issuer}/other`, fragment: `${issuer}/transactions/one/go#secret`,
          userinfo: issuer.replace('://', '://user:password@') + '/transactions/one/go',
          foreign: 'https://other.invalid/transactions/one/go', none: 'https://other.invalid/inert#fragment',
          'none-ready': `${issuer}/collect`, 'none-review': `${issuer}/collect`,
        }[mode];
        return res.end(JSON.stringify({ ...tx, status: mode === 'none' ? 'completed' : mode === 'none-review' ? 'awaiting_consent' : 'ready', transaction_token: 'transaction',
          next: { action: mode.startsWith('none') ? 'none' : 'continue', method: 'GET', url: target } }));
      }
      res.end(JSON.stringify({ redirect: 'https://rp.example/callback?code=code' }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const pair = await generateKeyPair('ES256', { extractable: true });
      const keystore = new MemoryKeystore();
      await keystore.put({ kid: 'test-key', handle: 'scout@example.com', issuer, privateJwk: await exportJWK(pair.privateKey),
        publicJwk: await exportJWK(pair.publicKey), createdAt: 0, status: 'active' });
      const client = new AgentLogin({ handle: 'scout@example.com', issuer, allowInsecure: true, keystore });
      const signingIn = client.signIn({ authorizationUrl: `${issuer}/authorize`, expectedHost: 'rp.example' });
      if (mode === 'query' || mode === 'descendant') {
        await signingIn;
        assert.equal(credentialRequests.length, 1);
        assert.ok(credentialRequests[0]!.startsWith('/transactions'));
      } else {
        const expected = mode === 'none' ? 'completed' : mode.startsWith('none-') ? 'protocol_error' : 'wrong_issuer';
        await assert.rejects(signingIn, (error: unknown) => error instanceof AgentLoginError && error.code === expected);
        assert.deepEqual(credentialRequests, [], 'no transaction bearer reaches an unbound or inert URL');
      }
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
}
