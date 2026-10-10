// The example application's sessions end on the server (reported against commit 9b6dd09: only the cookie expired).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createExample, SESSION_TTL } from '../../../examples/rp-hono/app.js';

test('#12 example sessions and Access Tokens expire on the server', async () => {
  let clock = 1_800_000_000;
  const { app, sessions, sweep } = createExample({ base: 'http://localhost:4000', issuer: 'http://localhost:3000', stateSecret: 'x'.repeat(40), now: () => clock });
  const agent = { iss: 'http://localhost:3000', sub: 'sub-1', key: 'http://localhost:3000 sub-1', handle: 'scout@example.com', scopes: ['openid'] };
  const live = { issuer: 'http://localhost:3000', accessToken: 'at', accessTokenExpiresAt: clock + 600, sub: 'sub-1' };
  sessions.set('sid-a', { agent, expiresAt: clock + SESSION_TTL, live: { ...live } });
  sessions.set('sid-b', { agent, expiresAt: clock + SESSION_TTL, live: { ...live } });
  const me = (sid: string) => app.request('http://localhost:4000/me', { headers: { cookie: `sid=${sid}` } });
  assert.equal((await me('sid-a')).status, 200);

  clock += 601; // the Access Token's lifetime has passed
  assert.equal((await me('sid-a')).status, 200, 'the session itself is still valid');
  assert.equal(sessions.get('sid-a')!.live, undefined, 'the expired Access Token is dropped when the session is read');
  sweep();
  assert.equal(sessions.get('sid-b')!.live, undefined, 'and by the sweep for sessions nobody reads');
  const notes = await app.request('http://localhost:4000/notes', { method: 'POST', headers: { cookie: 'sid=sid-a' } });
  assert.equal(notes.status, 401);
  assert.equal(((await notes.json()) as { error: string }).error, 'reauthentication_required');

  clock += SESSION_TTL; // a saved cookie replayed after the session's lifetime
  assert.equal((await me('sid-b')).status, 401);
  assert.equal(sessions.has('sid-b'), false, 'the expired session is removed');
  sessions.set('sid-c', { agent, expiresAt: clock - 1 });
  sweep();
  assert.equal(sessions.size, 0);
});
