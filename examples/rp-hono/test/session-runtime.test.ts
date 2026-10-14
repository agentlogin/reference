import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import type { Pool } from 'pg';
import { ApplicationSessionUncertainCommitError, PostgresSessionStore } from '../postgres-session-store.js';
import { SessionProtection } from '../session-store.js';
import { namespace, secret, session, sid } from './helpers.js';

class Connection extends EventEmitter {
  released?: boolean;
  releases = 0;
  statements: string[] = [];
  constructor(readonly pool: TestPool) { super(); }
  async query(sql: string) {
    this.statements.push(sql);
    if (sql === 'COMMIT' && this.pool.commitFailure) throw this.pool.commitFailure;
    if (sql === 'ROLLBACK' && this.pool.rollbackFails) throw new Error('socket gone');
    return { command: sql === 'COMMIT' ? this.pool.commitCommand : sql.split(' ')[0], rows: [], rowCount: 1 };
  }
  release(discard = false) { this.released = discard; this.releases++; }
}
class TestPool extends EventEmitter {
  connections: Connection[] = [];
  commitFailure?: Error;
  commitCommand = 'COMMIT';
  rollbackFails = false;
  ended = false;
  async connect() { const c = new Connection(this); this.connections.push(c); return c; }
  async end() { this.ended = true; }
  asPool() { return this as unknown as Pool; }
}

test('stored token encryption authenticates session identity, expiry, namespace and key', () => {
  const p = new SessionProtection(secret, namespace);
  const key = p.key(sid()), other = p.key(sid()), live = session(10_000).live!;
  const encrypted = p.encrypt(key, live);
  assert.deepEqual(p.decrypt(key, live.accessTokenExpiresAt, encrypted), live);
  assert.throws(() => p.decrypt(other, live.accessTokenExpiresAt, encrypted));
  assert.throws(() => p.decrypt(key, live.accessTokenExpiresAt + 1, encrypted));
  assert.throws(() => new SessionProtection(secret, 'other').decrypt(key, live.accessTokenExpiresAt, encrypted));
  assert.throws(() => new SessionProtection('changed-secret'.repeat(4), namespace).decrypt(key, live.accessTokenExpiresAt, encrypted));
  encrypted[encrypted.length - 1] ^= 1;
  assert.throws(() => p.decrypt(key, live.accessTokenExpiresAt, encrypted));
});

test('unknown logout commits never report success, retry, or keep a broken connection', async () => {
  const pool = new TestPool();
  pool.commitFailure = Object.assign(new Error('socket gone'), { code: 'ECONNRESET' });
  const store = new PostgresSessionStore({ pool: pool.asPool(), namespace, sessionSecret: secret });
  try {
    await assert.rejects(store.revoke(sid()), ApplicationSessionUncertainCommitError);
    assert.equal(pool.connections.length, 1);
    assert.equal(pool.connections[0].statements.filter((s) => s.startsWith('DELETE')).length, 1);
    assert.equal(pool.connections[0].released, true);
    assert.equal(pool.connections[0].releases, 1);
  } finally { await store.close(); }
  assert.equal(pool.ended, false);
  assert.equal(pool.listenerCount('error'), 0);
});

test('checked-out socket errors reject logout without an unhandled event or false success', async () => {
  const pool = new TestPool();
  pool.rollbackFails = true;
  const store = new PostgresSessionStore({ pool: pool.asPool(), namespace, sessionSecret: secret, onCheckpoint(e) {
    if (e.phase === 'before-commit') e.client.emit('error', new Error('injected connection loss'));
  } });
  try {
    await assert.rejects(store.revoke(sid()), /connection loss/);
    assert.equal(pool.connections[0].released, true);
    assert.equal(pool.connections[0].releases, 1);
    assert.equal(pool.connections[0].listenerCount('error'), 0);
  } finally { await store.close(); }
});

test('silent rollback cannot acknowledge logout and invalid input never checks out a connection', async () => {
  const pool = new TestPool();
  pool.commitCommand = 'ROLLBACK';
  const store = new PostgresSessionStore({ pool: pool.asPool(), namespace, sessionSecret: secret });
  try {
    for (const cookie of ['', 'sid-a', 'x'.repeat(44)]) {
      assert.equal(await store.get(cookie), undefined);
      await store.revoke(cookie);
    }
    for (const value of [null, '1000', Infinity, 0, 10001]) await assert.rejects(store.cleanup(value as number));
    assert.equal(pool.connections.length, 0);
    await assert.rejects(store.revoke(sid()), /rolled back/);
    assert.equal(pool.connections[0].releases, 1);
  } finally { await store.close(); }
});
