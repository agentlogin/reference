import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import type { Pool } from 'pg';
import { PostgresCallbackStateStore, UncertainCommitError } from '../src/index.js';

// Driver-level outcomes whose acknowledgement cannot be controlled with SQL scheduling alone.
class Connection extends EventEmitter {
  statements: string[] = [];
  released?: boolean;
  releaseCount = 0;
  constructor(readonly pool: TestPool) { super(); }
  async query(sql: string) {
    this.statements.push(sql);
    if (sql === 'COMMIT' && this.pool.commitFailure) throw this.pool.commitFailure;
    if (sql === 'ROLLBACK' && this.pool.rollbackFailure) throw new Error('connection gone');
    const rows = sql.includes('app_now_ms') ? [{ now: '1000' }]
      : sql.includes('FOR UPDATE') ? [{ expires_at: '2000', used: false }] : [];
    return { command: sql === 'COMMIT' ? this.pool.commitCommand : sql.split(' ')[0], rows, rowCount: 1 };
  }
  release(discard = false) { this.released = discard; this.releaseCount++; }
}
class TestPool extends EventEmitter {
  connections: Connection[] = [];
  ended = false;
  commitFailure?: Error;
  rollbackFailure = false;
  commitCommand = 'COMMIT';
  async connect() { const c = new Connection(this); this.connections.push(c); return c; }
  async end() { this.ended = true; }
  asPool() { return this as unknown as Pool; }
}

test('callback options reject missing/default connections and unsafe schema or timeout values', async () => {
  for (const options of [{}, { connectionString: '' }, { connectionString: 'test', pool: new TestPool().asPool() },
    { connectionString: 'test', schema: 'unsafe";drop' }, { connectionString: 'test', schema: 'pg_catalog' },
    { connectionString: 'test', maxConnections: 0 }, { connectionString: 'test', connectionTimeoutMs: 0 },
    { connectionString: 'test', lockTimeoutMs: Infinity }, { connectionString: 'test', statementTimeoutMs: -1 },
    { connectionString: 'test', idleTransactionTimeoutMs: 0 }]) {
    assert.throws(() => new PostgresCallbackStateStore(options));
  }
  const pool = new TestPool();
  const store = new PostgresCallbackStateStore({ pool: pool.asPool() });
  try {
    for (const key of ['', '\0', 'x'.repeat(1025)]) await assert.rejects(store.claim(key));
    for (const count of [0, -1, 1.5, 10001, NaN, null, '1000']) await assert.rejects(store.cleanup(count as number));
    assert.equal(pool.connections.length, 0, 'invalid input never checks out a connection');
  } finally { await store.close(); }
});

for (const code of ['ECONNRESET', '40001', '40P01']) {
  test(`failed COMMIT (${code}) never acknowledges or repeats a callback claim`, async () => {
    const pool = new TestPool();
    pool.commitFailure = Object.assign(new Error('commit outcome unavailable'), { code });
    const store = new PostgresCallbackStateStore({ pool: pool.asPool() });
    try {
      await assert.rejects(store.claim('pending'), UncertainCommitError);
      assert.equal(pool.connections.length, 1);
      assert.equal(pool.connections[0].statements.filter((s) => s.startsWith('UPDATE')).length, 1);
      assert.equal(pool.connections[0].released, true);
      assert.equal(pool.connections[0].releaseCount, 1);
    } finally { await store.close(); }
  });
}

test('a COMMIT answered with ROLLBACK is never successful', async () => {
  const pool = new TestPool();
  pool.commitCommand = 'ROLLBACK';
  const store = new PostgresCallbackStateStore({ pool: pool.asPool() });
  try {
    await assert.rejects(store.claim('pending'), /rolled back/);
    assert.equal(pool.connections.length, 1);
    assert.equal(pool.connections[0].releaseCount, 1);
  } finally { await store.close(); }
});

test('failed rollback discards the connection and preserves the original error', async () => {
  const pool = new TestPool();
  pool.rollbackFailure = true;
  const failure = new Error('original failure');
  const store = new PostgresCallbackStateStore({ pool: pool.asPool(), onCheckpoint(e) {
    if (e.phase === 'before-commit') throw failure;
  } });
  try {
    await assert.rejects(store.claim('pending'), (e) => e === failure);
    assert.equal(pool.connections[0].released, true);
    assert.equal(pool.connections[0].releaseCount, 1);
  } finally { await store.close(); }
});

test('external pool lifecycle and listeners remain with the owner', async () => {
  const pool = new TestPool();
  const received: Error[] = [];
  const owner = () => {};
  pool.on('error', owner);
  const store = new PostgresCallbackStateStore({ pool: pool.asPool(), onPoolError: (e) => received.push(e) });
  const failure = new Error('idle connection lost');
  pool.emit('error', failure);
  assert.deepEqual(received, [failure]);
  assert.equal(await store.claim('pending'), 'claimed');
  assert.equal(pool.connections[0].released, false);
  const statements = pool.connections[0].statements.join('\n');
  assert.match(statements, /BEGIN ISOLATION LEVEL READ COMMITTED/);
  assert.match(statements, /synchronous_commit/);
  await store.close();
  await store.close();
  assert.equal(pool.ended, false);
  assert.deepEqual(pool.listeners('error'), [owner]);
  await assert.rejects(store.claim('pending'), /closed/);
});
