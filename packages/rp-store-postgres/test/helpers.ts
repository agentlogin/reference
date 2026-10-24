import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { TestContext } from 'node:test';
import { Pool } from 'pg';
import { PostgresCallbackStateStore, type PostgresCallbackStateStoreOptions } from '../src/index.js';

export const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
export const skipPostgres = !connectionString && process.env.REQUIRE_POSTGRES_TESTS !== '1'
  ? 'AGENTLOGIN_TEST_POSTGRES_URL is not configured' : false;
export const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;

export async function fixture(t: TestContext, options: Partial<PostgresCallbackStateStoreOptions> & { realClock?: boolean } = {}) {
  assert.ok(connectionString, 'REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
  const schema = `rp_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new Pool({ connectionString, max: 4, connectionTimeoutMillis: 5_000 });
  const { realClock = false, ...overrides } = options;
  const store = new PostgresCallbackStateStore({ connectionString, schema, ...overrides });
  const peer = new PostgresCallbackStateStore({ connectionString, schema });
  t.after(async () => {
    await Promise.all([store.close(), peer.close()]);
    try { await admin.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`); }
    finally { await admin.end(); }
  });
  await store.migrate();
  let time = Date.now();
  if (!realClock) {
    await admin.query(`CREATE SEQUENCE ${quote(schema)}.test_clock START WITH ${time}`);
    await admin.query(`CREATE OR REPLACE FUNCTION ${quote(schema)}.app_now_ms() RETURNS bigint LANGUAGE sql VOLATILE SET search_path=pg_catalog AS 'SELECT last_value FROM ${quote(schema)}.test_clock'`);
  }
  const advance = async (ms: number) => {
    assert.equal(realClock, false);
    time += ms;
    await admin.query('SELECT setval($1::regclass, $2, true)', [`${schema}.test_clock`, time]);
  };
  return { store, peer, admin, schema, table: `${quote(schema)}.callback_states`, now: () => time, advance };
}

export async function eventually(check: () => Promise<boolean>, message: string) {
  const deadline = Date.now() + 5_000;
  do { if (await check()) return; await delay(10); } while (Date.now() < deadline);
  assert.fail(message);
}
