import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { test, type TestContext } from 'node:test';
import { serve } from '@hono/node-server';
import { AgentLogin, MemoryCookieJar, MemoryKeystore } from '../../../packages/agentlogin/src/index.js';
import { createIssuer } from '../../../packages/issuer/src/index.js';
import { PostgresCallbackStateStore } from '../../../packages/rp-store-postgres/src/index.js';
import { createExample } from '../app.js';
import { PostgresSessionStore } from '../postgres-session-store.js';
import { connectionString, fixture, quote, skipPostgres } from './helpers.js';

async function listen(t: TestContext, handler: (request: Request) => Response | Promise<Response>) {
  const server = serve({ fetch: handler, hostname: '127.0.0.1', port: 0 });
  t.after(async () => {
    await new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); });
  });
  if (!server.listening) await once(server, 'listening');
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

test('real sign-in starts on A, finishes on B, survives restart and logs out both application instances', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t, { realClock: true });
  let issuerHandler: (request: Request) => Response | Promise<Response> = () => new Response('starting', { status: 503 });
  const issuer = await listen(t, (request) => issuerHandler(request));
  const created = await createIssuer({ issuer, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  let exchanges = 0;
  issuerHandler = (request) => {
    if (new URL(request.url).pathname === '/token') exchanges++;
    return created.app.fetch(request);
  };
  let appHandler: (request: Request) => Response | Promise<Response> = () => new Response('starting', { status: 503 });
  const base = await listen(t, (request) => appHandler(request));
  const callbacksSchema = `${f.schema}_cb`;
  const callbackA = new PostgresCallbackStateStore({ connectionString, schema: callbacksSchema });
  const callbackB = new PostgresCallbackStateStore({ connectionString, schema: callbacksSchema });
  await callbackA.migrate();
  try {
    const options = { base, issuer, stateSecret: 'state-secret-shared-across-app-replicas'.repeat(2), handleDomains: ['example.com'] };
    const a = createExample({ ...options, callbackStore: callbackA, sessionStore: f.store });
    const b = createExample({ ...options, callbackStore: callbackB, sessionStore: f.peer });
    appHandler = (request) => a.app.fetch(request);
    const admin = async (path: string, body: unknown) => {
      const response = await fetch(`${issuer}${path}`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body) });
      assert.equal(response.ok, true);
      return response.json() as Promise<Record<string, string>>;
    };
    const owner = await admin('/admin/owners', { email: 'owner@example.com', name: 'Owner' });
    await admin('/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id, name: 'Scout' });
    const agent = new AgentLogin({ handle: 'scout@example.com', issuer, allowInsecure: true, keystore: new MemoryKeystore(), cookies: new MemoryCookieJar() });
    await agent.enroll({ credential: owner.credential! });
    const started = await a.app.request(`${base}/auth/agent/login?handle=scout%40example.com`);
    assert.equal(started.status, 302);
    const pendingCookie = started.headers.getSetCookie()[0]!.split(';')[0]!;
    const result = await agent.signIn({ authorizationUrl: started.headers.get('location')!, expectedHost: new URL(base).host });
    const callback = () => new Request(result.redirectUrl, { headers: { cookie: pendingCookie } });
    const signedIn = await b.app.fetch(callback());
    assert.equal(signedIn.status, 302);
    const sessionHeader = signedIn.headers.getSetCookie().find((value) => value.startsWith('sid='));
    assert.ok(sessionHeader);
    const cookie = sessionHeader.split(';')[0]!;
    const read = (app: typeof a.app) => app.request(`${base}/me`, { headers: { cookie } });
    const meA = await read(a.app), meB = await read(b.app);
    assert.equal(meA.status, 200);
    assert.equal(meB.status, 200);
    assert.match(meA.headers.get('cache-control')!, /no-store/);
    const identity = await meA.json();
    assert.deepEqual(await meB.json(), identity);
    assert.equal((identity as { handle: string }).handle, 'scout@example.com');
    assert.ok((identity as { first_seen: string }).first_seen);
    assert.equal(exchanges, 1);
    assert.equal((await a.app.fetch(callback())).status, 400, 'replaying on another app does not exchange the code again');
    assert.equal(exchanges, 1);
    assert.equal((await a.app.request(`${base}/notes`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ id: 'multi-host-note-1', text: 'Persists across replicas' }) })).status, 200, 'the successful token remains valid');

    const restartedStore = new PostgresSessionStore(f.config);
    try {
      const restarted = createExample({ ...options, callbackStore: callbackA, sessionStore: restartedStore });
      assert.deepEqual(await (await read(restarted.app)).json(), identity);
      const saved = await (await restarted.app.request(`${base}/notes`, { headers: { cookie } })).json() as { notes: Array<{ text: string }> };
      assert.equal(saved.notes[0]?.text, 'Persists across replicas');
      assert.equal((await b.app.request(`${base}/logout`, { method: 'POST', headers: { cookie } })).status, 200);
      for (const app of [a.app, b.app, restarted.app]) {
        assert.equal((await read(app)).status, 401);
        assert.equal((await app.request(`${base}/notes`, { method: 'POST', headers: { cookie } })).status, 401);
      }
    } finally { await restartedStore.close(); }
  } finally {
    await Promise.all([callbackA.close(), callbackB.close()]);
    await f.admin.query(`DROP SCHEMA ${quote(callbacksSchema)} CASCADE`);
  }
});
