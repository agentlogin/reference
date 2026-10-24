import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AgentLogin, AgentLoginError } from '../src/client.js';

test('application fetch combines caller cancellation with its per-request timeout', async () => {
  let requested = false;
  const server = http.createServer(() => { requested = true; });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    const client = new AgentLogin({ handle: 'scout@example.com', allowInsecure: true, timeoutMs: 10_000 });
    const started = Date.now();
    await assert.rejects(client.fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/slow`, { signal: AbortSignal.timeout(50) }), (e: unknown) => e instanceof AgentLoginError && e.code === 'network_error');
    assert.equal(requested, true);
    assert.ok(Date.now() - started < 1500, 'caller cancellation must not wait for the ten-second SDK timeout');
  } finally { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); }
});
