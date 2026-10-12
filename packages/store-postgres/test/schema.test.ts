import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PgDatabase } from '../src/runtime.js';
import { SCHEMA_VERSION } from '../src/schema.js';
import { fixture, prepareAgent, quote, skipPostgres } from './helpers.js';

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
