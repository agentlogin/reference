import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PgDatabase } from '../src/runtime.js';
import { SCHEMA_VERSION, schemaV1 } from '../src/schema.js';
import { PostgresStore } from '../src/postgres-store.js';
import type { Transaction } from '../../issuer/src/store.js';
import { asserted, codeFor, fixture, pending, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

const hasSqlState = (code: string) => (error: unknown) => !!error && typeof error === 'object' && 'code' in error && error.code === code;

test('PostgreSQL constraints preserve immutable owner and agent identities', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const { agent } = await prepareAgent(f.store, f.now(), 'identity');
  for (const [table, field] of [['owners', 'id'], ['owners', 'ownerSub'], ['agents', 'handle'], ['agents', 'sub'], ['agents', 'ownerId']]) {
    await assert.rejects(f.admin.query(
      `UPDATE ${quote(f.schema)}.${quote(table)} SET data=jsonb_set(data,ARRAY[$1]::text[],'"replacement"'::jsonb)`, [field],
    ), hasSqlState('23514'), `${table}.${field} must be immutable even through direct SQL`);
  }
  const owner = await f.store.getOwner('owner');
  assert.ok(owner);
  await assert.rejects(f.admin.query(`INSERT INTO ${quote(f.schema)}.owners(data) VALUES($1::jsonb)`, [{ ...owner, id: 'other-owner' }]), hasSqlState('23505'));
  await f.store.putOwner({ ...owner, name: 'Updated display name' });
  assert.equal((await f.store.getOwner(owner.id))?.name, 'Updated display name');
  assert.deepEqual(await f.store.getAgent(agent.handle), agent);
});

test('schema verification accepts only the matching installed migration version', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  await f.store.db.verifySchema();
  const absent = new PgDatabase({ pool: f.admin, schema: `${f.schema}_absent` });
  try {
    await assert.rejects(absent.verifySchema(), /not initialized.*agentlogin-migrate/);
  } finally { await absent.close(); }
  await f.admin.query(`DELETE FROM ${quote(f.schema)}.schema_migrations`);
  await assert.rejects(f.store.db.verifySchema(), /version none/);
  await f.admin.query(`INSERT INTO ${quote(f.schema)}.schema_migrations(version) VALUES($1)`, [SCHEMA_VERSION + 1]);
  await assert.rejects(f.store.db.verifySchema(), new RegExp(`version ${SCHEMA_VERSION + 1}`));
  await assert.rejects(f.store.migrate(), /newer than supported/);
  assert.equal((await f.admin.query(`SELECT version FROM ${quote(f.schema)}.schema_migrations`)).rows[0].version, SCHEMA_VERSION + 1);
});

test('schema version 2 upgrades existing key enrollments and their authorizations without loss', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const subject = await prepareAgent(f.store, f.now(), 'existing');
  const raw = await pending(f.store, f.now(), 'existing');
  const completed: Transaction = { ...asserted(raw, 'existing', f.now()), status: 'completed', terminalAt: f.now(), codeIssued: true, version: 2 };
  const key = { ...subject.key, status: 'active', challenge: undefined };
  const code = { ...codeFor(completed, f.now()), used: true };
  const token = tokenFor(completed, f.now());
  const schema = `${f.schema}_v1`;
  const legacy = new PostgresStore({ pool: f.admin, schema });
  try {
    await f.admin.query(`CREATE SCHEMA ${quote(schema)}`);
    await f.admin.query(`CREATE TABLE ${quote(schema)}.schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp()); INSERT INTO ${quote(schema)}.schema_migrations(version) VALUES(1)`);
    await f.admin.query(schemaV1(schema));
    await f.admin.query(`CREATE OR REPLACE FUNCTION ${quote(schema)}.app_now() RETURNS double precision LANGUAGE sql VOLATILE AS 'SELECT ${f.now()}::double precision'`);
    const records = {
      owners: await f.store.getOwner(subject.agent.ownerId), agents: subject.agent,
      credentials: await f.store.getCredential(subject.authorization.hash), keys: key,
      clients: await f.store.getClient(raw.clientId), transactions: completed, codes: code, access_tokens: token,
    };
    for (const [table, data] of Object.entries(records)) await f.admin.query(`INSERT INTO ${quote(schema)}.${quote(table)}(data) VALUES($1::jsonb)`, [data]);
    await assert.rejects(legacy.db.verifySchema(), /version 1/);
    await legacy.migrate();
    await legacy.migrate();
    await legacy.db.verifySchema();
    for (const [table, data] of Object.entries(records)) {
      assert.deepEqual((await f.admin.query(`SELECT data FROM ${quote(schema)}.${quote(table)}`)).rows[0].data, JSON.parse(JSON.stringify(data)), `${table} must survive migration`);
    }
    assert.deepEqual((await f.admin.query(`SELECT version FROM ${quote(schema)}.schema_migrations ORDER BY version`)).rows.map((row) => row.version), [1, 2]);
    const other = await prepareAgent(legacy, f.now(), 'other');
    const contender = { ...other.key, kid: key.kid, enrollment: 'new-pending' };
    assert.equal(await legacy.insertKey(contender, f.now(), other.authorization), 'ok');
    assert.equal((await legacy.getKey(key.kid, key.handle))?.status, 'active');
    assert.equal((await legacy.getKey(key.kid, contender.handle))?.status, 'pending');
    assert.equal(await legacy.redeemCode(code.hash, f.now()), 'used');
    assert.equal((await legacy.getAccessToken(token.hash))?.revoked, true, 'migrated replay evidence still revokes its token');
  } finally { await legacy.close(); await f.admin.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`); }
});
