import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { Pool } from 'pg';
import { PostgresSessionStore } from '../postgres-session-store.js';
import { SessionProtection } from '../session-store.js';
import { connectionString, eventually, fixture, namespace, quote, secret, session, sid, skipPostgres } from './helpers.js';

test('PostgreSQL application sessions, account history and logout are shared and survive restart', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  const original = await f.store.create(cookie, session(f.now()));
  assert.deepEqual(await f.peer.get(cookie), original);
  await f.store.close();
  const restarted = new PostgresSessionStore(f.config);
  try {
    await restarted.verifySchema();
    assert.deepEqual(await restarted.get(cookie), original);
    await f.advance(10);
    const replacement = sid();
    assert.equal((await restarted.create(replacement, session(f.now()), cookie)).firstSeen, original.firstSeen);
    assert.equal(await f.peer.get(cookie), undefined);
    assert.ok(await f.peer.get(replacement));
    await f.peer.revoke(replacement);
    assert.equal(await restarted.get(replacement), undefined);
    assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.accounts}`)).rows[0].count, '1');
  } finally { await restarted.close(); }
});

test('independent Node process recognizes the session and logs out every replica', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  await f.store.create(cookie, session(f.now()));
  const script = `import { PostgresSessionStore } from ${JSON.stringify(new URL('../postgres-session-store.ts', import.meta.url).href)};
    const store = new PostgresSessionStore({ connectionString: process.env.AGENTLOGIN_TEST_POSTGRES_URL, schema: process.argv[1], namespace: process.argv[2], sessionSecret: process.argv[3] });
    try { const s = await store.get(process.argv[4]); await store.revoke(process.argv[4]); process.stdout.write(JSON.stringify({ account: s?.agent.key, gone: (await store.get(process.argv[4])) === undefined })); }
    finally { await store.close(); }`;
  const result = await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script, f.schema, namespace, secret, cookie]);
  assert.deepEqual(JSON.parse(result.stdout), { account: 'https://issuer.example agent-1', gone: true });
  assert.equal(await f.peer.get(cookie), undefined);
});

test('cookie and Access Token are absent from stored plaintext; ciphertext cannot move between sessions', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const a = sid(), b = sid();
  await f.store.create(a, session(f.now()));
  await f.peer.create(b, session(f.now()));
  const p = new SessionProtection(secret, namespace);
  const rows = (await f.admin.query(`SELECT key,agent,live_ciphertext,live_expires_at FROM ${f.table}`)).rows;
  const raw = JSON.stringify(rows);
  assert.equal(raw.includes(a), false);
  assert.equal(raw.includes(b), false);
  assert.equal(raw.includes(session(f.now()).live!.accessToken), false);
  const cipherA = rows.find((row) => row.key === p.key(a)).live_ciphertext as Buffer;
  const cipherB = rows.find((row) => row.key === p.key(b)).live_ciphertext as Buffer;
  assert.equal(cipherA.equals(cipherB), false, 'fresh random authenticated-encryption nonce per record');
  await f.admin.query(`UPDATE ${f.table} SET live_ciphertext=$1 WHERE key=$2`, [cipherA, p.key(b)]);
  await assert.rejects(f.peer.get(b), /authentic|stored|decrypt|unsupported/i);
  assert.equal((await f.store.get(a))!.live!.accessToken, session(f.now()).live!.accessToken);
});

test('secret or application namespace changes invalidate session lookup while account history survives secret rotation', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  const old = await f.store.create(cookie, session(f.now()));
  for (const override of [{ sessionSecret: 'new-session-secret'.repeat(4) }, { namespace: 'https://other.example' }]) {
    const changed = new PostgresSessionStore({ ...f.config, ...override });
    try {
      assert.equal(await changed.get(cookie), undefined);
      if ('sessionSecret' in override) assert.equal((await changed.create(sid(), session(f.now()))).firstSeen, old.firstSeen);
    } finally { await changed.close(); }
  }
});

test('expired live credentials are erased without ending the session or renewing its deadline', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  const original = await f.store.create(cookie, session(f.now()));
  await f.advance(600);
  const current = await f.peer.get(cookie);
  assert.equal(current!.expiresAt, original.expiresAt);
  assert.equal(current!.live, undefined);
  assert.equal((await f.admin.query(`SELECT live_ciphertext FROM ${f.table}`)).rows[0].live_ciphertext, null);
  await f.advance(3000);
  assert.equal(await f.peer.get(cookie), undefined);
  assert.equal(await f.store.cleanup(), 1);
});

test('cleanup is bounded and removes expired credentials before otherwise valid sessions', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookies = [sid(), sid(), sid()];
  for (const cookie of cookies) await f.store.create(cookie, session(f.now()));
  assert.equal(await f.store.cleanup(1), 0);
  await f.advance(600);
  assert.equal(await f.store.cleanup(1), 1);
  assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.table} WHERE live_ciphertext IS NOT NULL`)).rows[0].count, '2');
  assert.equal(await f.peer.cleanup(2), 2);
  await f.advance(3000);
  assert.equal(await f.store.cleanup(1), 1);
  assert.equal(await f.peer.cleanup(2), 2);
  assert.equal(await f.store.cleanup(), 0);
  for (const cookie of cookies) assert.equal(await f.peer.get(cookie), undefined);
  for (const invalid of [0, 10001, NaN, null, '1000']) await assert.rejects(f.store.cleanup(invalid as number));
});

test('creation racing on an existing session never overwrites its identity or expiry', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  const first = await f.store.create(cookie, session(f.now()));
  await assert.rejects(f.peer.create(cookie, session(f.now() + 10, 'other')));
  assert.deepEqual(await f.peer.get(cookie), first);
  assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.accounts}`)).rows[0].count, '1', 'failed creation leaves no partial account');
});

test('creation checks expiry after waiting for the previous session to be revoked', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const old = sid(), fresh = sid();
  await f.store.create(old, session(f.now()));
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`SELECT key FROM ${f.table} FOR UPDATE`);
    const result = f.peer.create(fresh, { ...session(f.now()), expiresAt: f.now() + 1 }, old);
    const rejected = assert.rejects(result, /expir|created/i);
    await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%${f.schema}%`])).rows[0].count) > 0, 'replacement waits on old session');
    await f.advance(1);
    await lock.query('COMMIT');
    await rejected;
    assert.ok(await f.store.get(old), 'failed replacement rolls back revocation');
    assert.equal(await f.peer.get(fresh), undefined);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('read expiry is fresh after a table-lock wait', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  await f.store.create(cookie, { ...session(f.now()), expiresAt: f.now() + 1 });
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`LOCK TABLE ${f.table} IN ACCESS EXCLUSIVE MODE`);
    const result = f.peer.get(cookie);
    await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%${f.schema}%`])).rows[0].count) > 0, 'read waits on table');
    await f.advance(1);
    await lock.query('COMMIT');
    assert.equal(await result, undefined);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('an unrelated session progresses while another session is locked', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const a = sid(), b = sid();
  await f.store.create(a, session(f.now()));
  await f.store.create(b, session(f.now(), 'other'));
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`SELECT key FROM ${f.table} WHERE key=$1 FOR UPDATE`, [new SessionProtection(secret, namespace).key(a)]);
    assert.ok(await f.peer.get(b));
    await f.peer.revoke(b);
    assert.equal(await f.store.get(b), undefined);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('get cannot resurrect a session deleted while expired credential cleanup waits', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const cookie = sid();
  await f.store.create(cookie, session(f.now()));
  await f.advance(600);
  const lock = await f.admin.connect();
  try {
    await lock.query('BEGIN');
    await lock.query(`DELETE FROM ${f.table}`);
    const result = f.peer.get(cookie);
    await eventually(async () => Number((await f.admin.query(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE $1`, [`%${f.schema}%`])).rows[0].count) > 0, 'credential cleanup waits for concurrent deletion');
    await lock.query('COMMIT');
    assert.equal(await result, undefined);
    assert.equal((await f.admin.query(`SELECT count(*) FROM ${f.table}`)).rows[0].count, '0');
  } finally { await lock.query('ROLLBACK'); lock.release(); }
});

test('unknown commits are never acknowledged or repeated; committed logout stays deleted', { skip: skipPostgres }, async (t) => {
  let failure: string | undefined;
  let attempts = 0;
  const f = await fixture(t, { onCheckpoint(e) {
    if (e.operation === failure && e.phase === 'after-commit') { attempts++; throw new Error('acknowledgement lost'); }
  } });
  const cookie = sid();
  failure = 'create';
  await assert.rejects(f.store.create(cookie, session(f.now())), /uncertain/i);
  assert.ok(await f.peer.get(cookie));
  failure = 'revoke';
  await assert.rejects(f.store.revoke(cookie), /uncertain/i);
  assert.equal(await f.peer.get(cookie), undefined);
  assert.equal(attempts, 2);
});

test('migration and verification work with a restricted runtime role and do not require session secrets in DDL', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t, { realClock: true });
  await Promise.all([f.store.migrate(), f.peer.migrate()]);
  const role = `role_${f.schema.slice(14)}`;
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 5_000 });
  const runtime = new PostgresSessionStore({ pool, schema: f.schema, namespace, sessionSecret: secret });
  await f.admin.query(`CREATE ROLE ${quote(role)}`);
  try {
    await f.admin.query(`GRANT USAGE ON SCHEMA ${quote(f.schema)} TO ${quote(role)};
      GRANT SELECT,INSERT,UPDATE,DELETE ON ${f.table},${f.accounts} TO ${quote(role)};
      GRANT SELECT ON ${quote(f.schema)}.app_schema_migrations TO ${quote(role)};
      GRANT EXECUTE ON FUNCTION ${quote(f.schema)}.app_now() TO ${quote(role)}`);
    await pool.query(`SET ROLE ${quote(role)}`);
    await runtime.verifySchema();
    const cookie = sid();
    await runtime.create(cookie, session(f.now()));
    assert.ok(await runtime.get(cookie));
    await runtime.revoke(cookie);
    assert.equal(await runtime.cleanup(), 0);
    await assert.rejects(runtime.migrate(), (e: any) => e.code === '42501');
  } finally {
    await runtime.close(); await pool.end();
    await f.admin.query(`DROP OWNED BY ${quote(role)}; DROP ROLE ${quote(role)}`);
  }
});
