import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AgentLogin, AgentLoginError, type SignInResult } from '../src/client.js';

const result = (redirectUrl = 'https://app.example/callback?code=synthetic'): SignInResult => ({
  handle: 'scout@example.com', issuer: 'https://issuer.example', scopes: ['openid'], redirectUrl,
  client: { client_id: 'client', client_type: 'open', redirect_host: new URL(redirectUrl).host },
});
function unusedBody() {
  const events = { reads: 0, canceled: false };
  const body = new ReadableStream<Uint8Array>({
    pull(controller) { events.reads += 1; controller.enqueue(new Uint8Array(1024)); controller.close(); },
    cancel() { events.canceled = true; },
  }, { highWaterMark: 0 });
  return { body, events };
}

test('signInAt cancels application redirects and invalid responses without buffering, preserving cookies', async (t) => {
  for (const status of [302, 200]) await t.test(String(status), async (t) => {
    const client = new AgentLogin({ handle: 'scout@example.com' });
    // This test exercises the application side without needing an issuer, enrolled key or external network.
    t.mock.method(client as unknown as { discoverWithin(): Promise<unknown> }, 'discoverWithin', async () => ({
      issuer: 'https://issuer.example', metadata: { authorization_endpoint: 'https://issuer.example/authorize' },
    }));
    const { body, events } = unusedBody();
    t.mock.method(globalThis, 'fetch', async () => new Response(body, { status, headers: {
      location: 'https://issuer.example/authorize', 'set-cookie': 'pending=synthetic; Secure; Path=/',
    } }));
    await assert.rejects(client.signInAt('https://app.example/login', { deadlineMs: 1000 }),
      (error: unknown) => error instanceof AgentLoginError && error.code === (status === 302 ? 'no_key' : 'no_authorization_request'));
    assert.deepEqual(events, { reads: 0, canceled: true });
    assert.equal(await client.cookies.header(new URL('https://app.example/callback')), 'pending=synthetic');
  });
});

test('signInAt cancellation remains inside its original deadline', async (t) => {
  const client = new AgentLogin({ handle: 'scout@example.com' });
  t.mock.method(client as unknown as { discoverWithin(): Promise<unknown> }, 'discoverWithin', async () => ({
    issuer: 'https://issuer.example', metadata: { authorization_endpoint: 'https://issuer.example/authorize' },
  }));
  let finish!: () => void;
  const cancellation = new Promise<void>((resolve) => { finish = resolve; });
  let canceled = false;
  t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
    cancel() { canceled = true; return cancellation; },
  }), { status: 302, headers: { location: 'https://issuer.example/authorize' } }));
  try {
    await assert.rejects(client.signInAt('https://app.example/login', { deadlineMs: 50 }),
      (error: unknown) => error instanceof AgentLoginError && error.code === 'timeout');
    assert.equal(canceled, true);
  } finally { finish(); }
});

test('follow cancels redirect bodies before following and carries their cookies forward', async (t) => {
  const client = new AgentLogin({ handle: 'scout@example.com' });
  const { body, events } = unusedBody();
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async (_input: unknown, init: RequestInit) => {
    requests += 1;
    if (requests === 1) return new Response(body, { status: 302, headers: { location: '/done', 'set-cookie': 'sid=synthetic; Secure; Path=/' } });
    assert.equal(new Headers(init.headers).get('cookie'), 'sid=synthetic');
    assert.equal(events.canceled, true);
    return new Response('signed in');
  });
  assert.equal((await client.follow(result())).body, 'signed in');
  assert.equal(requests, 2);
  assert.deepEqual(events, { reads: 0, canceled: true });
});

test('follow cancels rejected, malformed and off-host redirect bodies', async (t) => {
  for (const [location, code, redirects] of [
    ['/next', 'callback_failed', 0],
    ['http://app.example/next', 'insecure_redirect', 5],
    ['http://[', 'ERR_INVALID_URL', 5],
    ['https://other.example/next', undefined, 5],
  ] as const) await t.test(location, async (t) => {
    const client = new AgentLogin({ handle: 'scout@example.com' });
    const { body, events } = unusedBody();
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(body, { status: 302, headers: { location } }));
    if (code) await assert.rejects(client.follow(result(), redirects), (error: unknown) => (error as { code?: string }).code === code);
    else assert.equal((await client.follow(result(), redirects)).body, '');
    assert.equal(fetch.mock.callCount(), 1);
    assert.deepEqual(events, { reads: 0, canceled: true });
  });
});

test('follow cancels final responses above the default 1 MiB limit even with a false Content-Length', async (t) => {
  const client = new AgentLogin({ handle: 'scout@example.com' });
  let canceled = false, chunks = 0;
  t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (chunks === 18) controller.close();
      else { chunks += 1; controller.enqueue(new Uint8Array(64 * 1024)); }
    },
    cancel() { canceled = true; },
  }, { highWaterMark: 0 }), { headers: { 'content-length': '1' } }));
  await assert.rejects(client.follow(result()), (error: unknown) => error instanceof AgentLoginError && error.code === 'response_too_large');
  assert.equal(canceled, true);
  assert.equal(chunks, 17, 'stop on the first chunk exceeding the byte limit');
});

test('follow counts decoded bytes and preserves UTF-8 characters split across chunks', async (t) => {
  for (const [text, limit, accepted] of [['€a', 4, true], ['€😀', 4, false], ['\uFEFF€😀', 10, true]] as const) {
    await t.test(`${JSON.stringify(text)} / ${limit}`, async (t) => {
      const bytes = new TextEncoder().encode(text);
      let offset = 0, canceled = false;
      t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream<Uint8Array>({
        pull(controller) {
          if (offset === bytes.length) controller.close();
          else controller.enqueue(bytes.slice(offset, ++offset));
        },
        cancel() { canceled = true; },
      }, { highWaterMark: 0 })));
      const client = new AgentLogin({ handle: 'scout@example.com', maxFollowBodyBytes: limit });
      if (accepted) assert.equal((await client.follow(result())).body, text.replace(/^\uFEFF/, ''));
      else {
        await assert.rejects(client.follow(result()), (error: unknown) => error instanceof AgentLoginError && error.code === 'response_too_large');
        assert.equal(canceled, true);
      }
    });
  }
});

test('follow body limit rejects invalid configuration and accepts empty responses', async (t) => {
  for (const maxFollowBodyBytes of [0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => new AgentLogin({ handle: 'scout@example.com', maxFollowBodyBytes }), /positive safe integer/);
  }
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 204 }));
  assert.equal((await new AgentLogin({ handle: 'scout@example.com', maxFollowBodyBytes: 1 }).follow(result())).body, '');
});

test('follow retains the request timeout while consuming a stalled response body', async () => {
  let received = false;
  const server = http.createServer((_req, res) => { received = true; res.writeHead(200); res.write('partial'); });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new AgentLogin({ handle: 'scout@example.com', allowInsecure: true, timeoutMs: 500 });
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/callback`;
    await assert.rejects(client.follow(result(url)), (error: unknown) => (error as Error).name === 'AbortError' || (error as Error).name === 'TimeoutError');
    assert.equal(received, true);
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});
