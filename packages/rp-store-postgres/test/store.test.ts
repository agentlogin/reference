import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { once } from 'node:events';
import { Pool, type PoolClient } from 'pg';
import { PostgresCallbackStateStore, UncertainCommitError } from '../src/index.js';
import { callbackContract } from '../../rp/test/callback-contract.js';
import { connectionString, eventually, fixture, quote, skipPostgres } from './helpers.js';

test('PostgreSQL runs the shared callback contract', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await callbackContract(f.store, f.now, f.advance);
});

test('independent connections and restarted stores retain exactly one claim', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const registrations = await Promise.all(Array.from({ length: 16 }, (_, i) =>
    (i % 2 ? f.store : f.peer).register('race', f.now() + 60_000)));
  assert.equal(registrations.filter(Boolean).length, 1);
  const claims = await Promise.all(Array.from({ length: 16 }, (_, i) => (i % 2 ? f.store : f.peer).claim('race')));
  assert.equal(claims.filter((v) => v === 'claimed').length, 1);
  assert.equal(claims.filter((v) => v === 'duplicate').length, 15);
  await f.store.close();
  const restarted = new PostgresCallbackStateStore({ connectionString, schema: f.schema });
  try {
    await restarted.verifySchema();
    assert.equal(await restarted.claim('race'), 'duplicate');
    assert.equal(await restarted.register('race', f.now() + 90_000), false);
    assert.equal(await restarted.claim('lost'), 'missing');
  } finally { await restarted.close(); }
});

test('independent Node processes consume the callback only once', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await f.store.register('processes', f.now() + 60_000);
  const moduleUrl = new URL('../src/index.ts', import.meta.url).href;
  const script = `import { PostgresCallbackStateStore } from ${JSON.stringify(moduleUrl)};
    const store = new PostgresCallbackStateStore({ connectionString: process.env.AGENTLOGIN_TEST_POSTGRES_URL, schema: process.argv[1] });
    try { process.stdout.write(await store.claim('processes')); } finally { await store.close(); }`;
  const results = await Promise.all(Array.from({ length: 6 }, () => promisify(execFile)(process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', script, f.schema])));
  assert.equal(results.filter((r) => r.stdout === 'claimed').length, 1);
  assert.equal(results.filter((r) => r.stdout === 'duplicate').length, 5);
});

for (const used of [false, true]) {
  test(`claim checks expiry after a no-op lock wait (used=${used})`, { skip: skipPostgres }, async (t) => {
    const f = await fixture(t);
    await f.store.register('waiting', f.now() + 100);
    if (used) await f.store.claim('waiting');
    const lock = await f.admin.connect();
    try {
      await lock.query('BEGIN');
      await lock.query(`SELECT key FROM ${f.table} WHERE key='waiting' FOR UPDATE`);
      const result = f.peer.claim('waiting');
      await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%${f.schema}%FOR UPDATE%`])).rows[0].count) > 0, 'claim waits on the row lock');
      await f.advance(100);
      await lock.query('COMMIT');
      assert.equal(await result, 'missing');
      assert.equal((await f.admin.query(`SELECT used FROM ${f.table} WHERE key='waiting'`)).rows[0].used, used);
    } finally { await lock.query('ROLLBACK'); lock.release(); }
  });
}

for (const blockerCommits of [false, true]) {
  test(`registration rechecks expiry after unique-index wait (blocker commits=${blockerCommits})`, { skip: skipPostgres }, async (t) => {
    const f = await fixture(t);
    const lock = await f.admin.connect();
    try {
      await lock.query('BEGIN');
      await lock.query(`INSERT INTO ${f.table}(key,expires_at,used) VALUES ('waiting',$1,false)`, [f.now() + 1_000]);
      const result = f.peer.register('waiting', f.now() + 100);
      const rejected = assert.rejects(result, /expir|registration/i);
      await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%INSERT%${f.schema}%`])).rows[0].count) > 0, 'registration waits on uniqueness');
      await f.advance(100);
      await lock.query(blockerCommits ? 'COMMIT' : 'ROLLBACK');
      await rejected;
      const row = await f.admin.query(`SELECT expires_at FROM ${f.table} WHERE key='waiting'`);
      assert.equal(row.rowCount, blockerCommits ? 1 : 0);
      if (blockerCommits) assert.equal(Number(row.rows[0].expires_at), f.now() + 900);
      assert.equal(await f.peer.register('recovered', f.now() + 1_000), true);
    } finally { await lock.query('ROLLBACK'); lock.release(); }
  });
}

test('an unrelated callback progresses while another row is locked', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await f.store.register('blocked', f.now() + 1_000);
  await f.store.register('free', f.now() + 1_000);
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`SELECT key FROM ${f.table} WHERE key='blocked' FOR UPDATE`);
    assert.equal(await f.peer.claim('free'), 'claimed');
    assert.equal(await f.peer.register('also-free', f.now() + 1_000), true);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('claim checks expiry after a maintenance table lock, before its UPDATE lock upgrade', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await f.store.register('table-wait', f.now() + 100);
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`LOCK TABLE ${f.table} IN SHARE MODE`);
    const result = f.peer.claim('table-wait');
    await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%${f.schema}%`])).rows[0].count) > 0, 'claim waits on the table lock');
    await f.advance(100);
    await lock.query('COMMIT');
    assert.equal(await result, 'missing');
    assert.equal((await f.admin.query(`SELECT used FROM ${f.table} WHERE key='table-wait'`)).rows[0].used, false);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('cleanup is bounded, skips locked records and preserves live consumed records', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  for (const key of ['a','b','c']) await f.store.register(key, f.now() + 100);
  await f.store.register('live', f.now() + 1_000);
  await f.store.claim('a');
  await f.store.claim('live');
  assert.equal(await f.store.cleanup(2), 0);
  await f.advance(100);
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`SELECT key FROM ${f.table} WHERE key='a' FOR UPDATE`);
    assert.equal(await f.peer.cleanup(1), 1);
    assert.equal(await f.peer.cleanup(2), 1);
    assert.equal(await f.peer.cleanup(2), 0);
    assert.equal(await f.peer.claim('live'), 'duplicate');
  } finally { await lock.query('ROLLBACK'); lock.release(); }
  assert.equal(await f.store.cleanup(2), 1);
  assert.equal(await f.peer.claim('a'), 'missing');
  assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.table}`)).rows[0].count, '1');
});

test('rolled back claims are not acknowledged and uncertain commits never repeat claims', { skip: skipPostgres }, async (t) => {
  let phase: string | undefined;
  let failures = 0;
  const f = await fixture(t, { onCheckpoint(event) {
    if (event.operation === 'claim' && event.phase === phase) { failures++; throw new Error('injected response loss'); }
  } });
  await f.store.register('rollback', f.now() + 1_000);
  phase = 'before-commit';
  await assert.rejects(f.store.claim('rollback'), /injected/);
  assert.equal(await f.peer.claim('rollback'), 'claimed');
  await f.store.register('uncertain', f.now() + 1_000);
  phase = 'after-commit';
  await assert.rejects(f.store.claim('uncertain'), UncertainCommitError);
  assert.equal(await f.peer.claim('uncertain'), 'duplicate');
  assert.equal(failures, 2, 'no automatic repetition of either operation');
  phase = undefined;
  assert.equal(await f.store.register('healthy', f.now() + 1_000), true);
  assert.equal(await f.store.claim('healthy'), 'claimed');
});

test('lock timeout rolls back and releases the connection for a later independent sign-in', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t, { maxConnections: 1, lockTimeoutMs: 100 });
  await f.store.register('blocked', f.now() + 1_000);
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`SELECT key FROM ${f.table} WHERE key='blocked' FOR UPDATE`);
    await assert.rejects(f.store.claim('blocked'), (error: any) => error.code === '55P03');
    assert.equal(await f.store.register('independent', f.now() + 1_000), true);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
  assert.equal(await f.peer.claim('blocked'), 'claimed');
});

test('schema migration is concurrent, idempotent and refuses unknown versions', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await f.admin.query(`DROP SCHEMA ${quote(f.schema)} CASCADE`);
  await assert.rejects(f.store.verifySchema(), /not initialized/);
  await Promise.all([f.store.migrate(), f.peer.migrate()]);
  await f.store.migrate();
  await Promise.all([f.store.verifySchema(), f.peer.verifySchema()]);
  await f.admin.query(`UPDATE ${quote(f.schema)}.schema_migrations SET version=99`);
  await assert.rejects(f.store.verifySchema(), /version|schema|migration/i);
  await assert.rejects(f.peer.migrate(), /version|schema|migration/i);
});

test('a disconnected checked-out client fails closed without an unhandled error or leaked claim', { skip: skipPostgres }, async (t) => {
  let release!: () => void;
  const resume = new Promise<void>((resolve) => { release = resolve; });
  let ready!: (client: PoolClient) => void;
  const locked = new Promise<PoolClient>((resolve) => { ready = resolve; });
  const f = await fixture(t, { onCheckpoint: async (e) => {
    if (e.operation === 'claim' && e.phase === 'after-lock') { ready(e.client); await resume; }
  } });
  await f.store.register('disconnect', f.now() + 1_000);
  const result = f.store.claim('disconnect');
  const rejected = assert.rejects(result, /terminat|connection|queryable/i);
  try {
    const client = await locked;
    const pid = Number((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    const error = once(client, 'error');
    await f.admin.query('SELECT pg_terminate_backend($1)', [pid]);
    await error;
    release();
    await rejected;
    assert.equal(await f.peer.claim('disconnect'), 'claimed', 'unacknowledged pre-commit work rolled back');
    assert.equal(await f.store.register('reconnected', f.now() + 1_000), true);
  } finally { release(); }
});

test('database clock is epoch milliseconds and invalid values never create records', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t, { realClock: true });
  const now = Number((await f.admin.query(`SELECT ${quote(f.schema)}.app_now_ms() AS now`)).rows[0].now);
  assert.ok(Math.abs(now - Date.now()) < 5_000);
  for (const [key, expiry] of [['', now + 1000], ['bad', NaN], ['bad', Infinity], ['bad', 1.5], ['bad', -1], ['bad', Number.MAX_SAFE_INTEGER + 1]] as const) {
    await assert.rejects(f.store.register(key, expiry));
  }
  await assert.rejects(f.store.register('expired', now - 1));
  assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.table}`)).rows[0].count, '0');
});

test('bounded external pool acquisition fails closed and recovers without ending the owner pool', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 100 });
  const store = new PostgresCallbackStateStore({ pool, schema: f.schema });
  const held = await pool.connect();
  try {
    await assert.rejects(store.claim('absent'), /timeout|time.?out/i);
  } finally { held.release(); }
  try {
    assert.equal(await store.register('recovered', f.now() + 1_000), true);
    assert.equal(await store.claim('recovered'), 'claimed');
    await store.close();
    assert.equal((await pool.query('SELECT 1 AS alive')).rows[0].alive, 1);
  } finally { await store.close(); await pool.end(); }
});

test('runtime operations work with DML privileges and cannot migrate', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t, { realClock: true });
  const role = `${f.schema}_role`;
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 5_000 });
  const store = new PostgresCallbackStateStore({ pool, schema: f.schema });
  await f.admin.query(`CREATE ROLE ${quote(role)}`);
  try {
    await f.admin.query(`GRANT USAGE ON SCHEMA ${quote(f.schema)} TO ${quote(role)};
      GRANT SELECT, INSERT, UPDATE, DELETE ON ${f.table} TO ${quote(role)};
      GRANT SELECT ON ${quote(f.schema)}.schema_migrations TO ${quote(role)};
      GRANT EXECUTE ON FUNCTION ${quote(f.schema)}.app_now_ms() TO ${quote(role)}`);
    await pool.query(`SET ROLE ${quote(role)}`);
    await store.verifySchema();
    assert.equal(await store.register('least-privilege', Date.now() + 60_000), true);
    assert.equal(await store.claim('least-privilege'), 'claimed');
    assert.equal(await store.cleanup(), 0);
    await assert.rejects(store.migrate(), (error: any) => error.code === '42501');
  } finally {
    await store.close();
    await pool.end();
    await f.admin.query(`DROP OWNED BY ${quote(role)}; DROP ROLE ${quote(role)}`);
  }
});
