// Application sessions are shared independently of one-use callback state.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { MemoryCallbackStateStore, RelyingPartyError, type SignIn } from '@agentlogin/rp';
import { createExample, SESSION_TTL } from '../../../examples/rp-hono/app.js';
import { MemorySessionStore, type SessionStore } from '../../../examples/rp-hono/session-store.js';

const issuer = 'https://issuer.example';
const base = 'http://localhost:4000';
const agent = { iss: issuer, sub: 'sub-1', key: `${issuer} sub-1`, handle: 'scout@example.com', scopes: ['openid'] };
const newSid = () => randomBytes(32).toString('base64url');
const noStore = (r: Response) => assert.match(r.headers.get('cache-control') ?? '', /(?:^|,\s*)no-store(?:,|$)/);
const cookie = (sid: string, secure = false) => `${secure ? '__Host-sid' : 'sid'}=${sid}`;
function fixture() {
  let clock = Math.floor(Date.now() / 1000);
  const now = () => clock;
  const store = new MemorySessionStore(now);
  const callbackStore = new MemoryCallbackStateStore();
  const make = (sessionStore: SessionStore = store, url = base) => createExample({
    base: url, issuer, stateSecret: 'x'.repeat(40), callbackStore, sessionStore, now,
  });
  const session = (lifetime = SESSION_TTL, tokenLifetime = 600) => ({
    agent, expiresAt: now() + lifetime,
    live: { issuer, accessToken: 'private-live-token', accessTokenExpiresAt: now() + tokenLifetime, sub: agent.sub },
  });
  return { store, make, session, now, advance: (seconds: number) => { clock += seconds; } };
}
function wrappedStore(store: SessionStore, overrides: Partial<SessionStore>): SessionStore {
  return {
    create: (...args) => store.create(...args), get: (...args) => store.get(...args),
    revoke: (...args) => store.revoke(...args), cleanup: (...args) => store.cleanup(...args), close: () => store.close(),
    ...overrides,
  };
}
// Retain real cookie sealing, preflight and callback consumption; stub only the upstream exchange.
async function callbackRequest(example: ReturnType<typeof createExample>, signIn: SignIn, oldSid?: string, url = base) {
  const state = randomBytes(24).toString('hex');
  example.rp.begin = async () => ({ url: `${issuer}/authorize?state=${state}`, pending: { state, issuer, nonce: 'nonce', verifier: 'verifier' } });
  let exchanges = 0;
  example.rp.complete = async () => { exchanges++; return signIn; };
  const start = await example.app.request(`${url}/auth/agent/login`);
  assert.equal(start.status, 302);
  noStore(start);
  const pendingCookie = start.headers.getSetCookie().find((value) => value.includes(`al_${state}=`))!.split(';')[0]!;
  const callback = `${url}/auth/agent/callback?${new URLSearchParams({ state, iss: issuer, code: 'code' })}`;
  const headers = { cookie: [pendingCookie, oldSid ? cookie(oldSid, url.startsWith('https:')) : undefined].filter(Boolean).join('; ') };
  return { request: () => example.app.request(callback, { headers }), exchanges: () => exchanges };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

test('example sessions and Access Tokens expire on the server, including sessions nobody reads', async () => {
  const f = fixture();
  const { app, sweep } = f.make();
  const a = newSid(); const b = newSid();
  await f.store.create(a, f.session()); await f.store.create(b, f.session());
  const me = (sid: string) => app.request(`${base}/me`, { headers: { cookie: cookie(sid) } });
  assert.equal((await me(a)).status, 200);
  f.advance(600);
  const response = await me(a);
  assert.equal(response.status, 200, 'the application session can outlive its Access Token');
  noStore(response);
  assert.equal((await f.store.get(a))!.live, undefined);
  await sweep();
  assert.equal(await f.store.cleanup(), 0, 'sweep already removed expired credentials from the unread session');
  assert.equal((await f.store.get(b))!.live, undefined);
  const notes = await app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(a) } });
  assert.equal(notes.status, 401);
  assert.equal((await notes.json() as { error: string }).error, 'reauthentication_required');
  noStore(notes);
  f.advance(SESSION_TTL - 600);
  assert.equal((await me(b)).status, 401, 'a saved cookie cannot outlive its server-side deadline');
  assert.equal(await f.store.get(b), undefined);
});

test('sessions, account firstSeen and logout are shared by independent application instances', async () => {
  const f = fixture(); const a = f.make(); const b = f.make(); const sid = newSid();
  const original = await f.store.create(sid, f.session());
  for (const example of [a, b]) {
    const response = await example.app.request(`${base}/me`, { headers: { cookie: cookie(sid) } });
    assert.equal(response.status, 200);
    assert.equal((await response.json() as { first_seen: string }).first_seen, original.firstSeen);
    noStore(response);
  }
  const logout = await b.app.request(`${base}/logout`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(logout.status, 200); assert.deepEqual(await logout.json(), { signed_out: true }); noStore(logout);
  assert.match(logout.headers.get('set-cookie')!, /Max-Age=0/);
  assert.equal((await a.app.request(`${base}/me`, { headers: { cookie: cookie(sid) } })).status, 401);
  f.advance(10);
  assert.equal((await f.store.create(newSid(), f.session())).firstSeen, original.firstSeen, 'logout does not recreate the account');
});

test('a successful HTTPS sign-in rotates the existing session and issues a protected opaque cookie', async () => {
  const f = fixture(); const secureBase = 'https://app.example'; const example = f.make(f.store, secureBase);
  const oldSid = newSid(); const original = await f.store.create(oldSid, f.session());
  const callback = await callbackRequest(example, { agent, issuer, claims: {}, accessToken: 'private-live-token', accessTokenExpiresAt: f.now() + 600 }, oldSid, secureBase);
  const response = await callback.request(); assert.equal(response.status, 302); noStore(response);
  const issued = response.headers.getSetCookie().find((value) => value.startsWith('__Host-sid='))!;
  assert.ok(issued);
  for (const flag of [/; Path=\//, /; HttpOnly/, /; Secure/, /; SameSite=Lax/]) assert.match(issued, flag);
  assert.doesNotMatch(issued, /Domain=|private-live-token|sub-1/);
  const sid = issued.slice('__Host-sid='.length).split(';')[0]!;
  assert.match(sid, /^[A-Za-z0-9_-]{43}$/); assert.notEqual(sid, oldSid);
  assert.equal(await f.store.get(oldSid), undefined);
  assert.equal((await f.store.get(sid))!.firstSeen, original.firstSeen);
  assert.equal(callback.exchanges(), 1);
});

test('session creation failure returns 503 without issuing a session or releasing callback state', async () => {
  const f = fixture();
  const example = f.make(wrappedStore(f.store, { create: async () => { throw new Error('private database failure'); } }));
  const callback = await callbackRequest(example, { agent, issuer, claims: {}, accessToken: 'private-live-token', accessTokenExpiresAt: f.now() + 600 });
  const response = await callback.request(); assert.equal(response.status, 503); noStore(response);
  assert.equal(response.headers.getSetCookie().some((value) => /^sid=/.test(value)), false);
  assert.doesNotMatch(await response.text(), /private database failure|private-live-token/);
  assert.equal((await callback.request()).status, 400);
  assert.equal(callback.exchanges(), 1, 'session store failure cannot replay the code exchange');
});

test('session reads fail closed with 503 and no sensitive error details', async () => {
  const f = fixture(); const example = f.make(wrappedStore(f.store, { get: async () => { throw new Error('private database failure'); } }));
  for (const [path, method] of [['/me', 'GET'], ['/notes', 'POST']]) {
    const response = await example.app.request(`${base}${path}`, { method, headers: { cookie: cookie(newSid()) } });
    assert.equal(response.status, 503); noStore(response); assert.doesNotMatch(await response.text(), /private database failure|saved/);
  }
});

test('logout storage failure cannot report success or clear the usable session cookie', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session());
  const example = f.make(wrappedStore(f.store, { revoke: async () => { throw new Error('offline'); } }));
  const response = await example.app.request(`${base}/logout`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(response.status, 503); noStore(response); assert.doesNotMatch(await response.text(), /signed_out/);
  assert.equal(response.headers.get('set-cookie'), null); assert.ok(await f.store.get(sid));
});

test('a temporary UserInfo failure rejects the action but preserves the application session', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session()); const example = f.make();
  example.rp.recheck = async () => { throw new RelyingPartyError('userinfo_failed', 'upstream unavailable'); };
  const response = await example.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(response.status, 503); noStore(response); assert.equal(response.headers.get('set-cookie'), null); assert.ok(await f.store.get(sid));
});

test('UserInfo revocation invalidates the session for every application instance', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session()); const a = f.make(); const b = f.make();
  a.rp.recheck = async () => { throw new RelyingPartyError('revoked', 'revoked'); };
  const response = await a.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(response.status, 401); noStore(response); assert.equal(await f.store.get(sid), undefined);
  assert.equal((await b.app.request(`${base}/me`, { headers: { cookie: cookie(sid) } })).status, 401);
});

test('a delayed UserInfo failure cannot clear a newer sign-in cookie', async () => {
  const f = fixture(); const oldSid = newSid(); await f.store.create(oldSid, f.session());
  const secureBase = 'https://app.example';
  const oldRequestApp = f.make(f.store, secureBase), loginApp = f.make(f.store, secureBase);
  const entered = deferred(), finish = deferred();
  oldRequestApp.rp.recheck = async () => { entered.resolve(); await finish.promise; throw new RelyingPartyError('revoked', 'revoked'); };
  const pending = oldRequestApp.app.request(`${secureBase}/notes`, { method: 'POST', headers: { cookie: cookie(oldSid, true) } });
  await entered.promise;
  const callback = await callbackRequest(loginApp, { agent, issuer, claims: {}, accessToken: 'new-live-token', accessTokenExpiresAt: f.now() + 600 }, oldSid, secureBase);
  const signedIn = await callback.request();
  assert.equal(signedIn.status, 302);
  const newCookie = signedIn.headers.getSetCookie().find((value) => value.startsWith('__Host-sid='))!.split(';')[0]!;
  finish.resolve();
  const failed = await pending;
  assert.equal(failed.status, 401);
  assert.equal(failed.headers.get('set-cookie'), null, 'an old automatic response cannot erase the new cookie');
  assert.equal((await loginApp.app.request(`${secureBase}/me`, { headers: { cookie: newCookie } })).status, 200);
  assert.equal(await f.store.get(oldSid), undefined);
});

test('a failed session revalidation after UserInfo cannot authorize the action', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session());
  let reads = 0;
  const example = f.make(wrappedStore(f.store, {
    get: async (key) => { if (++reads === 2) throw new Error('offline after UserInfo'); return f.store.get(key); },
  }));
  example.rp.recheck = async () => ({ sub: agent.sub });
  const response = await example.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(response.status, 503); noStore(response); assert.doesNotMatch(await response.text(), /saved/);
  assert.equal(reads, 2); assert.ok(await f.store.get(sid));
});

test('failed durable revocation after UserInfo does not pretend the session ended', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session());
  const example = f.make(wrappedStore(f.store, { revoke: async () => { throw new Error('offline'); } }));
  example.rp.recheck = async () => { throw new RelyingPartyError('revoked', 'revoked'); };
  const response = await example.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid) } });
  assert.equal(response.status, 503); noStore(response); assert.equal(response.headers.get('set-cookie'), null);
  assert.ok(await f.store.get(sid));
});

for (const change of ['logout', 'session expiry', 'Access Token expiry'] as const) {
  test(`the action rechecks ${change} after waiting for UserInfo`, async () => {
    const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session()); const a = f.make(); const b = f.make();
    const entered = deferred(); const finish = deferred();
    a.rp.recheck = async () => { entered.resolve(); await finish.promise; return { sub: agent.sub }; };
    const pending = a.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid) } });
    await entered.promise;
    if (change === 'logout') {
      const response = await b.app.request(`${base}/logout`, { method: 'POST', headers: { cookie: cookie(sid) } });
      assert.equal(response.status, 200, 'logout does not wait for the upstream request');
    } else f.advance(change === 'session expiry' ? SESSION_TTL : 600);
    finish.resolve();
    const response = await pending; assert.equal(response.status, 401); noStore(response); assert.doesNotMatch(await response.text(), /saved/);
  });
}

test('same-origin browser mutations and agent requests work; cross-origin mutations do not', async () => {
  const f = fixture(); const sid = newSid(); await f.store.create(sid, f.session()); const example = f.make();
  let checks = 0; example.rp.recheck = async () => { checks++; return { sub: agent.sub }; };
  for (const headers of [{ origin: base }, {}]) {
    const response = await example.app.request(`${base}/notes`, { method: 'POST', headers: { cookie: cookie(sid), ...headers } });
    assert.equal(response.status, 200); noStore(response);
  }
  assert.equal(checks, 2);
  for (const headers of [{ origin: 'https://attacker.example' }, { origin: 'null' }, { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' }]) {
    for (const path of ['/notes', '/logout']) {
      const response = await example.app.request(`${base}${path}`, { method: 'POST', headers: { cookie: cookie(sid), ...headers } });
      assert.equal(response.status, 403); noStore(response);
    }
  }
  assert.equal(checks, 2, 'rejected browser requests never reach UserInfo');
  assert.ok(await f.store.get(sid), 'rejected logout cannot invalidate the session');
});

test('application session cleanup is bounded and preserves active sessions', async () => {
  const f = fixture(); const expired = [newSid(), newSid(), newSid()];
  for (const sid of expired) await f.store.create(sid, f.session(10));
  const active = newSid(); await f.store.create(active, f.session()); f.advance(10);
  assert.equal(await f.store.cleanup(2), 2); assert.equal(await f.store.cleanup(2), 1); assert.equal(await f.store.cleanup(2), 0);
  assert.ok(await f.store.get(active));
  for (const sid of expired) assert.equal(await f.store.get(sid), undefined);
});
