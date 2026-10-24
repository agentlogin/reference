import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AgentLogin, AgentLoginError, MemoryCookieJar, MemoryKeystore } from '../src/index.js';

test('native request timeout keeps its classification even before the overall timer, while caller cancellation stays distinct', async (t) => {
  const timeout = new AbortController();
  t.mock.method(AbortSignal, 'timeout', () => timeout.signal);
  t.mock.method(globalThis, 'fetch', async (_url: unknown, init: RequestInit) => {
    timeout.abort(new DOMException('native request deadline', 'TimeoutError'));
    throw init.signal!.reason;
  });
  const al = new AgentLogin({ handle: 'scout@example.com', issuer: 'https://issuer.example' });
  await assert.rejects(al.fetch('https://app.example'), (e: unknown) => e instanceof AgentLoginError && e.code === 'timeout');
  // Both signals are now aborted, but AbortSignal.any records the caller as the first input/winner.
  await assert.rejects(al.fetch('https://app.example', { signal: AbortSignal.abort(new Error('caller cancelled')) }),
    (e: unknown) => e instanceof AgentLoginError && e.code === 'network_error');
});

test('cookie headers prefer longer paths and preserve creation order when replacing equal-path cookies', async () => {
  const jar = new MemoryCookieJar();
  const url = new URL('https://app.example/account/settings');
  await jar.store(url, ['sid=root; Path=/', 'first=1; Path=/account', 'sid=account; Path=/account', 'last=3; Path=/account']);
  assert.equal(await jar.header(url), 'first=1; sid=account; last=3; sid=root');
  await jar.store(url, ['first=updated; Path=/account', 'sid=new-account; Path=/account']);
  assert.equal(await jar.header(url), 'first=updated; sid=new-account; last=3; sid=root');
  await jar.store(url, ['first=deleted; Path=/account; Max-Age=0', 'first=recreated; Path=/account']);
  assert.equal(await jar.header(url), 'sid=new-account; last=3; first=recreated; sid=root');
});

for (const entry of ['signIn', 'signInAt'] as const) {
  test(`deadline includes slow discovery for ${entry}`, async () => {
    const requests: string[] = [];
    const server = http.createServer((req, res) => {
      requests.push(req.url!);
      const timer = setTimeout(() => res.end('{}'), 400);
      res.on('close', () => clearTimeout(timer));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const al = new AgentLogin({ handle: 'scout@example.com', issuer: url, allowInsecure: true });
      const started = performance.now();
      const result = entry === 'signIn'
        ? al.signIn({ authorizationUrl: `${url}/authorize`, expectedHost: 'rp.example', deadlineMs: 60 })
        : al.signInAt(`${url}/login`, { deadlineMs: 60 });
      await assert.rejects(result, (e: unknown) => e instanceof AgentLoginError && e.code === 'timeout');
      assert.ok(performance.now() - started < 250, 'discovery used the overall deadline, not its 10-second request budget');
      // Under load the shared deadline can expire during DNS/connection setup, before HTTP reaches the server.
      assert.ok(requests.length <= 1 && requests.every((url) => url === '/.well-known/openid-configuration'), 'no request beyond discovery started');
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
}

for (const slowAt of ['/login', '/next', '/authorize']) {
  test(`signInAt shares one deadline through application redirects and authorization: ${slowAt}`, async () => {
    // Leave room for metadata and loopback scheduling before the chosen slow step. The two fast redirects
    // plus the slow authorization response still exceed one budget, but not a wrongly restarted budget.
    const deadlineMs = 1_000;
    let url = '';
    const requests: string[] = [];
    const server = http.createServer((req, res) => {
      const path = new URL(req.url!, url).pathname;
      requests.push(path);
      if (path === '/.well-known/openid-configuration') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ issuer: url, authorization_endpoint: `${url}/authorize`, token_endpoint: `${url}/token`, userinfo_endpoint: `${url}/userinfo`, jwks_uri: `${url}/jwks`, transaction_endpoint: `${url}/transactions`, agents_endpoint: `${url}/agents`, handle_domains: ['example.com'], agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'] }));
        return;
      }
      const timer = setTimeout(() => {
        if (path === '/authorize') { res.writeHead(400); res.end('{}'); }
        else { res.writeHead(302, { location: path === '/login' ? '/next' : '/authorize' }); res.end(); }
      }, path === slowAt ? (slowAt === '/authorize' ? 750 : 4_000) : 200);
      res.on('close', () => clearTimeout(timer));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const keystore = new MemoryKeystore();
      await keystore.put({ kid: 'placeholder', handle: 'scout@example.com', issuer: url, privateJwk: {}, publicJwk: {}, createdAt: 0, status: 'active' });
      const al = new AgentLogin({ handle: 'scout@example.com', issuer: url, allowInsecure: true, keystore });
      const started = performance.now();
      await assert.rejects(al.signInAt(`${url}/login`, { deadlineMs }), (e: unknown) => e instanceof AgentLoginError && e.code === 'timeout');
      assert.ok(performance.now() - started < 2_500, 'redirects and protocol steps do not restart the overall budget');
      assert.equal(requests.at(-1), slowAt, 'no subsequent request started');
      assert.equal(requests.filter((p) => p === '/.well-known/openid-configuration').length, 1, 'one discovery is reused throughout this sign-in');
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
}
