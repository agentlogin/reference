import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { MemoryCallbackStateStore } from '@agentlogin/rp';
import { createExample } from '../app.js';
import { MemorySessionStore } from '../session-store.js';
import { listenPort, readinessCheck } from '../server-config.js';

const base = 'https://workspace.example';
const options = { base, issuer: 'https://identity.example', stateSecret: 'deployment-state-secret'.repeat(3), callbackStore: new MemoryCallbackStateStore(), sessionStore: new MemorySessionStore() };

test('internal PORT is independent of the public TLS origin and rejects ambiguous values', () => {
  assert.equal(listenPort(new URL(base), '8080'), 8080);
  assert.equal(listenPort(new URL('http://localhost:4321')), 4321);
  assert.equal(listenPort(new URL(base)), 4000);
  for (const value of ['', '0', '65536', '-1', '1.5', ' 4000', '4000 ', '04', '1e3', 'Infinity']) {
    assert.throws(() => listenPort(new URL(base), value));
  }
});

test('a production process never silently falls back to local development', async () => {
  const root = fileURLToPath(new URL('../../..', import.meta.url));
  const env = { ...process.env, NODE_ENV: 'production' };
  delete env.BASE_URL;
  await assert.rejects(promisify(execFile)(process.execPath, ['--import', 'tsx', 'examples/rp-hono/server.ts'], { cwd: root, env, timeout: 5_000 }),
    (error: NodeJS.ErrnoException & { stderr?: string }) => !!error.stderr?.includes('Production requires an explicit HTTPS BASE_URL'));
});

test('readiness is read-only, coalesced, cached briefly and recovers after a failed probe', async () => {
  let now = 10_000, calls = 0, fail = false;
  let complete!: () => void;
  let wait = new Promise<void>((resolve) => { complete = resolve; });
  const ready = readinessCheck(async () => { calls++; await wait; if (fail) throw new Error('private connection details'); }, () => now);
  const requests = Array.from({ length: 100 }, () => ready());
  await Promise.resolve();
  assert.equal(calls, 1);
  complete();
  assert.deepEqual(await Promise.all(requests), Array(100).fill(true));
  assert.equal(await ready(), true);
  assert.equal(calls, 1);
  now += 2_000; fail = true; wait = Promise.resolve();
  assert.equal(await ready(), false);
  assert.equal(calls, 2);
  fail = false;
  assert.equal(await ready(), false);
  now += 2_000;
  assert.equal(await ready(), true);
  assert.equal(calls, 3);
});

test('health reveals no storage details, while readiness fails closed without caching or cookies', async () => {
  const { app } = createExample({ ...options, ready: async () => { throw new Error('postgresql://username:secret@private.internal/db'); } });
  const live = await app.request(base + '/healthz');
  assert.equal(live.status, 200);
  assert.deepEqual(await live.json(), { status: 'alive' });
  const ready = await app.request(base + '/readyz');
  assert.equal(ready.status, 503);
  assert.deepEqual(await ready.json(), { status: 'unavailable' });
  for (const response of [live, ready]) {
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('set-cookie'), null);
  }
});

test('the public HTTPS configuration applies host-only HSTS across response boundaries', async () => {
  const { app } = createExample({ ...options, ready: async () => false });
  for (const [path, status] of [
    ['/', 200], ['/workspace', 200], ['/client-metadata.json', 200], ['/healthz', 200],
    ['/me', 401], ['/auth/agent/callback', 400], ['/not-found', 404], ['/readyz', 503],
  ] as const) {
    // The application may receive HTTP after a proxy has terminated public TLS.
    const response = await app.request('http://127.0.0.1:8080' + path);
    assert.equal(response.status, status, path);
    assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000', path);
  }
});

test('loopback HTTP development does not advertise HSTS', async () => {
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    const localBase = `http://${host}:4000`;
    const { app } = createExample({ ...options, base: localBase });
    const response = await app.request(localBase + '/', { headers: { 'x-forwarded-proto': 'https' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('strict-transport-security'), null);
  }
});

test('public pilot smoke checks the actual application and rejects metadata tampering and oversized bodies', async () => {
  // JavaScript operator tooling deliberately runs without a TypeScript loader in the deployed source checkout.
  const { smoke, readJson, origin } = await import('../../../deploy/pilot/acceptance.mjs');
  const { app } = createExample(options);
  assert.deepEqual(await smoke(base, (url: string, init: RequestInit) => app.request(url, init)), { publicSmoke: true });
  for (const value of ['http://workspace.example', 'https://u:p@workspace.example', base + '/path', base + '/?secret=yes']) assert.throws(() => origin(value));
  await assert.rejects(smoke(base, async (url: string, init: RequestInit) => {
    const result = await app.request(url, init);
    if (url.endsWith('/client-metadata.json')) return Response.json({ ...await result.json(), redirect_uris: ['https://other.example/callback'] });
    return result;
  }));
  let cancelled = false;
  const huge = new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(65 * 1024)); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'application/json' } });
  await assert.rejects(readJson(huge, 200), /exceeded/);
  assert.equal(cancelled, true);
});
