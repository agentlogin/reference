import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { TestContext } from 'node:test';
import { Pool } from 'pg';
import { PostgresStore, type PostgresStoreOptions } from '../src/postgres-store.js';
import type { AgentKey, Code, Store, Transaction, AccessToken } from '../../issuer/src/store.js';

export const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
export const required = process.env.REQUIRE_POSTGRES_TESTS === '1';
export const skipPostgres = !connectionString && !required ? 'AGENTLOGIN_TEST_POSTGRES_URL is not configured' : false;
export const quote = (name: string): string => `"${name.replaceAll('"', '""')}"`;

/** Never connects to an implicit/default database. Each test owns one random schema. */
export async function fixture(t: TestContext, options: Partial<PostgresStoreOptions> & { realClock?: boolean } = {}) {
  assert.ok(connectionString, 'REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
  const schema = `agentlogin_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new Pool({ connectionString, max: 3, connectionTimeoutMillis: 5_000 });
  const { realClock = false, ...storeOptions } = options;
  const store = new PostgresStore({ connectionString, schema, maxRetries: 12, retryBaseMs: 2, ...storeOptions });
  const peer = new PostgresStore({ connectionString, schema, maxRetries: 12, retryBaseMs: 2 });
  let time = 1_700_000_000;
  t.after(async () => {
    await Promise.all([store.close(), peer.close()]);
    try { await admin.query(`DROP SCHEMA IF EXISTS ${quote(schema)} CASCADE`); }
    finally { await admin.end(); }
  });
  await store.migrate();
  if (!realClock) {
    // Sequence state is not MVCC-snapshotted. A table would hide clock advances from a
    // SERIALIZABLE transaction that established its snapshot before waiting for a lock.
    await admin.query(`CREATE SEQUENCE ${quote(schema)}.test_clock START WITH ${time}`);
    await admin.query(`CREATE OR REPLACE FUNCTION ${quote(schema)}.app_now() RETURNS double precision LANGUAGE sql VOLATILE AS 'SELECT last_value::double precision FROM ${quote(schema)}.test_clock'`);
  }
  const advance = async (seconds: number): Promise<void> => {
    assert.equal(realClock, false, 'a real clock cannot be shifted');
    time += seconds;
    await admin.query('SELECT setval($1::regclass, $2, true)', [`${schema}.test_clock`, time]);
  };
  return { store, peer, admin, schema, now: () => time, advance };
}

export async function prepareAgent(store: Store, now: number, id: string, ownerId = 'owner') {
  await store.putOwner({ id: ownerId, ownerSub: `sub-${ownerId}`, email: `${ownerId}@example.com`, emailVerified: true, verifiedVia: 'passkey', createdAt: now });
  const agent = { handle: `${id}@example.com`, local: id, domain: 'example.com', sub: `sub-${id}`, ownerId, preferredUsername: id, enabled: true, authorizationVersion: 0, createdAt: now };
  assert.equal(await store.putAgent(agent), true);
  const credential = { hash: `credential-${id}`, ownerId, kind: 'owner' as const, sessionAuth: 'passkey' as const, createdAt: now };
  await store.putCredential(credential);
  const authorization = { ...credential, agentSub: agent.sub };
  const key: AgentKey = { kid: `key-${id}`, handle: agent.handle, agentSub: agent.sub, enrollment: `enrollment-${id}`, status: 'pending', jwk: { kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y' }, permissions: { share_owner: false }, createdAt: now, expiresAt: now + 3_600, challenge: { value: 'challenge', expiresAt: now + 300 } };
  assert.equal(await store.insertKey(key, now, authorization), 'ok');
  assert.equal(await store.activateKey(key.kid, key.enrollment, 'challenge', now), true);
  return { agent, key, authorization };
}

export async function pending(store: Store, now: number, id: string, clientId = 'client', lifetime = 300): Promise<Transaction> {
  await store.putClient({ clientId, type: 'registered', redirectUris: ['https://rp.example/cb'], requireReview: false, tokenEndpointAuthMethod: 'none' });
  const transaction: Transaction = {
    id, version: 0, clientId, redirectUri: 'https://rp.example/cb', scopes: ['openid'], state: 'state', nonce: 'nonce', codeChallenge: 'challenge',
    disclosure: [], status: 'awaiting_agent', challenge: 'challenge', createdAt: now, expiresAt: now + lifetime,
    acceptDisclosure: true, deliverToSession: false, ownerApprovalOutstanding: false, reviewOutstanding: false, passedCap: false,
    continueSecret: 'continue', codeIssued: false, transactionTokenHash: `transaction-token-${id}`,
  };
  await store.insertTransaction(transaction);
  return transaction;
}

export const asserted = (transaction: Transaction, id: string, now: number, ownerId = 'owner'): Transaction => ({
  ...transaction, status: 'ready', challenge: undefined, handle: `${id}@example.com`, kid: `key-${id}`, keyEnrollment: `enrollment-${id}`,
  agentSub: `sub-${id}`, agentVersion: 0, accountVersion: 0, ownerId, assertedAt: now,
});

export async function begin(store: Store, now: number, id: string, txnId: string, clientId = 'client', maxSignups?: number, ownerId = 'owner') {
  const transaction = await pending(store, now, txnId, clientId);
  const result = await store.updateTransaction(asserted(transaction, id, now, ownerId), transaction.version, { now, maxSignups });
  assert.ok(result);
  return result;
}

export const codeFor = (transaction: Transaction, now: number): Code => ({
  hash: `code-${transaction.id}`, txnId: transaction.id, clientId: transaction.clientId, redirectUri: transaction.redirectUri,
  codeChallenge: transaction.codeChallenge, nonce: transaction.nonce, scopes: transaction.scopes, handle: transaction.handle!, kid: transaction.kid!,
  keyEnrollment: transaction.keyEnrollment!, agentSub: transaction.agentSub!, agentVersion: transaction.agentVersion!, accountVersion: transaction.accountVersion!,
  authTime: now, expiresAt: now + 60, used: false, voided: false,
});

export const tokenFor = (transaction: Transaction, now: number): AccessToken => ({
  hash: `access-${transaction.id}`, txnId: transaction.id, clientId: transaction.clientId, handle: transaction.handle!, kid: transaction.kid!,
  keyEnrollment: transaction.keyEnrollment!, agentSub: transaction.agentSub!, agentVersion: transaction.agentVersion!, accountVersion: transaction.accountVersion!,
  scopes: transaction.scopes, expiresAt: now + 600, revoked: false,
});

export function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

export async function eventually(check: () => Promise<boolean>, message: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  do { if (await check()) return; await delay(10); } while (Date.now() < deadline);
  assert.fail(message);
}
