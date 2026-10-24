import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { TestContext } from 'node:test';
import { Pool } from 'pg';
import { PostgresSessionStore, type PostgresSessionStoreOptions } from '../postgres-session-store.js';
import type { NewSession } from '../session-store.js';

export const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
export const skipPostgres = !connectionString && process.env.REQUIRE_POSTGRES_TESTS !== '1'
  ? 'AGENTLOGIN_TEST_POSTGRES_URL is not configured' : false;
export const secret = 'application-session-test-secret'.repeat(3);
export const namespace = 'https://app.example';
export const sid = () => randomBytes(32).toString('base64url');
export const quote = (v: string) => `"${v.replaceAll('"', '""')}"`;

export async function fixture(t: TestContext, options: Partial<PostgresSessionStoreOptions> & { realClock?: boolean } = {}) {
  assert.ok(connectionString, 'REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
  const schema = `sessions_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new Pool({ connectionString, max: 4, connectionTimeoutMillis: 5_000 });
  const { realClock = false, ...overrides } = options;
  const config = { connectionString, schema, namespace, sessionSecret: secret, ...overrides };
  const store = new PostgresSessionStore(config);
  const peer = new PostgresSessionStore({ ...config, onCheckpoint: undefined });
  t.after(async () => {
    await Promise.all([store.close(), peer.close()]);
    try { await admin.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`); }
    finally { await admin.end(); }
  });
  await store.migrate();
  let time = Math.floor(Date.now() / 1000);
  if (!realClock) {
    await admin.query(`CREATE SEQUENCE ${quote(schema)}.test_clock START WITH ${time}`);
    await admin.query(`CREATE OR REPLACE FUNCTION ${quote(schema)}.app_now() RETURNS bigint LANGUAGE sql VOLATILE SET search_path=pg_catalog AS 'SELECT last_value FROM ${quote(schema)}.test_clock'`);
  }
  const advance = async (seconds: number) => {
    assert.equal(realClock, false);
    time += seconds;
    await admin.query('SELECT setval($1::regclass,$2,true)', [`${schema}.test_clock`, time]);
  };
  return { store, peer, admin, schema, config, table: `${quote(schema)}.app_sessions`, accounts: `${quote(schema)}.app_accounts`, now: () => time, advance };
}

export function session(now: number, subject = 'agent-1'): NewSession {
  return {
    agent: { iss: 'https://issuer.example', sub: subject, key: `https://issuer.example ${subject}`, handle: 'scout@example.com', scopes: ['openid'] },
    expiresAt: now + 3600,
    live: { issuer: 'https://issuer.example', sub: subject, accessToken: `sensitive-access-token-${subject}`, accessTokenExpiresAt: now + 600 },
  };
}
export async function eventually(check: () => Promise<boolean>, message: string) {
  const deadline = Date.now() + 5_000;
  do { if (await check()) return; await delay(10); } while (Date.now() < deadline);
  assert.fail(message);
}
