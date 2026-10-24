import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { MemoryCookieJar } from 'agentlogin';
import { MemoryCallbackStateStore } from '@agentlogin/rp';
import { createExample } from '../app.js';
import { MemorySessionStore } from '../session-store.js';

const base = 'https://workspace.example';
const issuer = 'https://issuer.example';

async function fixture() {
  const store = new MemorySessionStore();
  const sid = randomBytes(32).toString('base64url');
  await store.create(sid, {
    agent: { iss: issuer, sub: 'pilot-agent', key: issuer + ' pilot-agent', scopes: ['openid'] },
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  });
  const { app } = createExample({ base, issuer, stateSecret: 'acceptance-state-secret'.repeat(3), callbackStore: new MemoryCallbackStateStore(), sessionStore: store });
  const cookies = new MemoryCookieJar();
  await cookies.store(new URL(base), [`__Host-sid=${sid}; Path=/; Secure; HttpOnly; Max-Age=3600`]);
  const request = async (path: string, method = 'GET') => {
    const cookie = await cookies.header(new URL(base + path));
    const response = await app.request(base + path, { method, headers: cookie ? { cookie } : {} });
    await cookies.store(new URL(base + path), response.headers.getSetCookie());
    return response;
  };
  const replay = (url: string, init: RequestInit) => app.request(url, init);
  return { store, sid, cookies, request, replay };
}

test('pilot logout acceptance replays the retired cookie and verifies durable invalidation', async () => {
  const { logoutAndVerify } = await import('../../../deploy/pilot/acceptance.mjs');
  const f = await fixture();
  let replayed = false;
  await logoutAndVerify(base, f.cookies, f.request, (url: string, init: RequestInit) => {
    replayed = true;
    assert.equal(url, base + '/me');
    assert.equal(new Headers(init.headers).get('cookie'), `__Host-sid=${f.sid}`);
    assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    return f.replay(url, init);
  });
  assert.equal(replayed, true);
  assert.equal(await f.cookies.header(new URL(base + '/me')), undefined);
  assert.equal(await f.store.get(f.sid), undefined);
});

test('pilot logout acceptance rejects a cookie-only logout with a surviving server session', async () => {
  const { logoutAndVerify } = await import('../../../deploy/pilot/acceptance.mjs');
  const f = await fixture();
  f.store.revoke = async () => {}; // Mutant: the HTTP handler clears the jar but forgets durable invalidation.
  await assert.rejects(logoutAndVerify(base, f.cookies, f.request, f.replay), /Unexpected HTTP status/);
  assert.equal(await f.cookies.header(new URL(base + '/me')), undefined, 'the normal client looks signed out');
  assert.ok(await f.store.get(f.sid), 'the retired credential still authorizes requests');
});
