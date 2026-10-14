import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import type { Pool } from 'pg';
import { PgDatabase, UncertainCommitError } from '../src/runtime.js';

/** Minimal protocol double for outcomes that need driver-level injection, not a PostgreSQL scheduling fixture. */
class Connection extends EventEmitter {
  readonly statements: string[] = [];
  released?: boolean;
  constructor(private readonly pool: ConnectionPool) { super(); }
  async query(sql: string) {
    this.statements.push(sql);
    await this.pool.onQuery?.(this, sql);
    if (sql === 'COMMIT' && this.pool.commitFailure) throw this.pool.commitFailure;
    const command = sql === 'COMMIT' ? this.pool.commitCommand : sql.split(' ', 1)[0];
    const rows = sql.includes('.app_now()') ? [{ now: this.pool.clocks.shift() ?? 0 }] : [];
    return { command, rows, rowCount: rows.length, fields: [], oid: 0 };
  }
  release(poisoned = false) { this.released = poisoned; }
}
class ConnectionPool extends EventEmitter {
  readonly connections: Connection[] = [];
  clocks: number[] = [];
  commitCommand = 'COMMIT';
  commitFailure?: Error;
  onQuery?: (connection: Connection, sql: string) => void | Promise<void>;
  async connect() { const c = new Connection(this); this.connections.push(c); return c; }
  async end() {}
  asPool() { return this as unknown as Pool; }
}

for (const code of ['40001', '40P01']) {
  test(`runtime repeats all decisions with fresh time after confirmed ${code} rollback`, async () => {
    const pool = new ConnectionPool();
    pool.clocks = [100, 101, 102];
    const db = new PgDatabase({ pool: pool.asPool(), retryBaseMs: 0, maxRetries: 2 });
    const times: number[] = [];
    try {
      const result = await db.mutate('retry', async (s) => {
        times.push(await s.now());
        if (times.length < 3) throw Object.assign(new Error('confirmed rollback'), { code });
        return times.at(-1);
      });
      assert.equal(result, 102);
      assert.deepEqual(times, [100, 101, 102]);
      assert.equal(pool.connections.length, 3);
      assert.equal(pool.connections.filter((c) => c.statements.includes('ROLLBACK')).length, 2);
      assert.equal(pool.connections.filter((c) => c.statements.includes('COMMIT')).length, 1);
      assert(pool.connections.every((c) => c.released === false));
    } finally { await db.close(); }
  });
}

test('runtime bounds rollback retries and releases every checked-out connection', async () => {
  const pool = new ConnectionPool();
  const db = new PgDatabase({ pool: pool.asPool(), retryBaseMs: 0, maxRetries: 1 });
  let calls = 0;
  const failure = Object.assign(new Error('contention persists'), { code: '40001' });
  try {
    await assert.rejects(db.mutate('retry-limit', async () => { calls += 1; throw failure; }), (e) => e === failure);
    assert.equal(calls, 2);
    assert.equal(pool.connections.length, 2);
    assert(pool.connections.every((c) => c.statements.includes('ROLLBACK') && c.released === false));
  } finally { await db.close(); }
});

test('COMMIT that answers ROLLBACK cannot report a successful mutation', async () => {
  const pool = new ConnectionPool();
  pool.commitCommand = 'ROLLBACK';
  const db = new PgDatabase({ pool: pool.asPool() });
  let calls = 0;
  try {
    await assert.rejects(db.mutate('aborted', async () => { calls += 1; return 'incorrect-success'; }), /rolled back.*instead of committing/);
    assert.equal(calls, 1);
    assert.equal(pool.connections[0].released, false);
  } finally { await db.close(); }
});

test('an unknown COMMIT discards its connection and reconciles once without repeating the mutation', async () => {
  const pool = new ConnectionPool();
  pool.commitFailure = Object.assign(new Error('connection lost'), { code: 'ECONNRESET' });
  const db = new PgDatabase({ pool: pool.asPool() });
  let calls = 0, reconciliations = 0;
  try {
    const value = await db.mutate('uncertain', async () => { calls += 1; return 'candidate'; }, async () => {
      reconciliations += 1;
      pool.commitFailure = undefined;
      return { resolved: true, value: 'durable-result' };
    });
    assert.equal(value, 'durable-result');
    assert.equal(calls, 1);
    assert.equal(reconciliations, 1);
    assert.equal(pool.connections.length, 2);
    assert.equal(pool.connections[0].released, true);
    assert(pool.connections[1].statements.includes('BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY'));
  } finally { await db.close(); }
});

test('inconclusive recovery fails closed and never repeats an uncertain mutation', async () => {
  const pool = new ConnectionPool();
  const db = new PgDatabase({ pool: pool.asPool(), onCheckpoint: (event) => {
    if (event.phase === 'afterCommit') throw new Error('acknowledgement lost');
  } });
  let calls = 0;
  try {
    await assert.rejects(db.mutate('uncertain', async () => { calls += 1; return true; }, async () => ({ resolved: false })), UncertainCommitError);
    assert.equal(calls, 1);
    assert.equal(pool.connections[0].released, true);
  } finally { await db.close(); }
});

test('a retry-shaped fault after confirmed COMMIT never reruns committed work', async () => {
  const pool = new ConnectionPool();
  const db = new PgDatabase({ pool: pool.asPool(), onCheckpoint: (event) => {
    if (event.phase === 'afterCommit') throw Object.assign(new Error('post-commit failure'), { code: '40001' });
  } });
  let calls = 0;
  try {
    await assert.rejects(db.mutate('committed', async () => { calls += 1; return true; }), UncertainCommitError);
    assert.equal(calls, 1);
    assert.equal(pool.connections.length, 1);
    assert.equal(pool.connections[0].released, true);
  } finally { await db.close(); }
});

for (const operation of ['read', 'mutate', 'migrate'] as const) {
  test(`${operation} handles checked-out socket loss before COMMIT and discards the connection`, async () => {
    const pool = new ConnectionPool();
    const failure = Object.assign(new Error('socket lost between queries'), { code: 'ECONNRESET' });
    pool.onQuery = (client, sql) => {
      if (sql.startsWith('SELECT\n')) client.emit('error', failure);
    };
    const db = new PgDatabase({ pool: pool.asPool() });
    try {
      const result = operation === 'read' ? db.read(async () => true)
        : operation === 'mutate' ? db.mutate('socket-loss', async () => true) : db.migrate();
      await assert.rejects(result, (error) => error === failure);
      assert.equal(pool.connections.length, 1);
      assert.equal(pool.connections[0].released, true);
      assert(!pool.connections[0].statements.includes('COMMIT'));
      assert.equal(pool.connections[0].listenerCount('error'), 0);
    } finally { await db.close(); }
  });
}

for (const phase of ['during', 'after'] as const) {
  test(`socket loss ${phase} COMMIT remains uncertain even when shaped like a rollback error`, async () => {
    const pool = new ConnectionPool();
    const failure = Object.assign(new Error('socket lost'), { code: '40001' });
    if (phase === 'during') pool.onQuery = (client, sql) => { if (sql === 'COMMIT') client.emit('error', failure); };
    const db = new PgDatabase({ pool: pool.asPool(), onCheckpoint: ({ client, phase: checkpoint }) => {
      if (phase === 'after' && checkpoint === 'afterCommit') client.emit('error', failure);
    } });
    let calls = 0;
    try {
      await assert.rejects(db.mutate('socket-loss', async () => { calls++; return true; }), UncertainCommitError);
      assert.equal(calls, 1);
      assert.equal(pool.connections.length, 1);
      assert.equal(pool.connections[0].released, true);
      assert.equal(pool.connections[0].listenerCount('error'), 0);
    } finally { await db.close(); }
  });
}

test('migration with an uncertain COMMIT discards its connection and never reports success', async () => {
  const pool = new ConnectionPool();
  pool.onQuery = (client, sql) => { if (sql === 'COMMIT') client.emit('error', new Error('socket lost')); };
  const db = new PgDatabase({ pool: pool.asPool() });
  try {
    await assert.rejects(db.migrate(), UncertainCommitError);
    assert.equal(pool.connections.length, 1);
    assert.equal(pool.connections[0].released, true);
    assert.equal(pool.connections[0].listenerCount('error'), 0);
  } finally { await db.close(); }
});
