import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { MemoryCallbackStateStore } from '@agentlogin/rp';
import { createIssuer } from '../../../packages/issuer/src/index.js';
import { mintIdToken, userinfo } from '../../../packages/issuer/src/tokens.js';
import { PostgresStore } from '../../../packages/store-postgres/src/index.js';
import { PostgresCallbackStateStore } from '../../../packages/rp-store-postgres/src/index.js';
import { begin, codeFor, fixture, prepareAgent, quote, tokenFor } from '../../../packages/store-postgres/test/helpers.js';
import { createExample } from '../../../examples/rp-hono/app.js';
import { PostgresSessionStore } from '../../../examples/rp-hono/postgres-session-store.js';
import { session, sid } from '../../../examples/rp-hono/test/helpers.js';

const run = promisify(execFile);
const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL!;
const enabled = process.env.AGENTLOGIN_OPS_DISPOSABLE === '1';
const options = { skip: !enabled, timeout: 120_000 };
const bin = (name: string) => process.env.PG_BIN ? join(process.env.PG_BIN, name) : name;
const secret = 'disposable-ops-original-session-secret'.repeat(2);
const namespace = 'https://app.example';
const localUrl = () => {
  const url = new URL(connectionString);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/agentlogin_ops');
  assert.ok(process.env.AGENTLOGIN_OPS_WORK && process.env.AGENTLOGIN_OPS_OUTPUT);
  return url;
};
const evidence = (name: string, result: unknown) => writeFile(join(process.env.AGENTLOGIN_OPS_OUTPUT!, name + '.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });

test('an actual older backup revives authority until issuer, callback and application recovery fences are applied', options, async (t) => {
  const url = localUrl();
  const f = await fixture(t);
  const subject = await prepareAgent(f.store, f.now(), 'backup');
  const tx = await begin(f.store, f.now(), 'backup', 'backup-tx');
  const code = codeFor(tx, f.now());
  await f.store.completeTransaction(tx, tx.version, code, f.now());
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  const bearer = randomBytes(32).toString('base64url');
  const token = { ...tokenFor(tx, f.now()), hash: createHash('sha256').update(bearer).digest('base64url') };
  assert.equal(await f.store.insertAccessToken(token, f.now()), true);
  const issuer = await createIssuer({ issuer: 'https://issuer.example', handleDomains: ['example.com'], store: f.store, now: f.now });
  assert.equal((await userinfo(issuer.ctx, bearer)).sub, subject.agent.sub);

  const appSchema = `${f.schema}_app`, cbSchema = `${f.schema}_cb`;
  const app = new PostgresSessionStore({ connectionString, schema: appSchema, namespace, sessionSecret: secret });
  const callbacks = new PostgresCallbackStateStore({ connectionString, schema: cbSchema });
  await app.migrate(); await callbacks.migrate();
  const cookie = sid(), state = 'synthetic-pending-callback';
  const appSession = session(Math.floor(Date.now() / 1000));
  const original = await app.create(cookie, appSession);
  await app.saveNote(cookie, 'restore-rehearsal-note', 'Synthetic retained application data');
  await callbacks.register(state, Date.now() + 60_000);
  const archive = join(process.env.AGENTLOGIN_OPS_WORK!, 'before-revocation.dump');
  const pgArgs = ['-h', url.hostname, '-p', url.port, '-U', 'postgres', '-d', 'agentlogin_ops'];
  let restoredApp: PostgresSessionStore | undefined;
  let oldSecretApp: PostgresSessionStore | undefined;
  try {
    await run(bin('pg_dump'), [...pgArgs, '-Fc', '--no-owner', '--schema', f.schema, '--schema', appSchema, '--schema', cbSchema, '-f', archive], { timeout: 30_000 });
    await f.peer.revokeKey(subject.key.kid, subject.key.enrollment, f.now());
    await f.peer.deleteCredential(subject.authorization.hash);
    await app.revoke(cookie);
    assert.equal(await callbacks.claim(state), 'claimed');
    await assert.rejects(userinfo(issuer.ctx, bearer));
    assert.equal(await app.get(cookie), undefined);
    assert.notEqual(await callbacks.claim(state), 'claimed');

    // The isolated restore intentionally demonstrates the dangerous baseline before any traffic is permitted.
    await f.admin.query(`DROP SCHEMA ${quote(f.schema)},${quote(appSchema)},${quote(cbSchema)} CASCADE`);
    await run(bin('pg_restore'), [...pgArgs, '--no-owner', '--no-privileges', '--exit-on-error', archive], { timeout: 30_000 });
    assert.equal((await f.store.getKey(subject.key.kid))?.status, 'active');
    assert.ok(await f.store.getCredential(subject.authorization.hash));
    assert.equal((await userinfo(issuer.ctx, bearer)).sub, subject.agent.sub);
    assert.ok(await app.get(cookie));
    assert.equal((await f.admin.query(`SELECT count(*) FROM ${quote(cbSchema)}.callback_states WHERE NOT used`)).rows[0].count, '1');

    // Reconcile the known immutable identity; unknown post-backup history stays quarantined in production.
    assert.equal(await f.store.revokeAllKeys(subject.agent.handle, subject.authorization, f.now()), true);
    await f.store.deleteCredential(subject.authorization.hash);
    await f.store.setAgentEnabled(subject.agent.handle, false, subject.agent.sub, f.now());
    await f.admin.query(`DELETE FROM ${quote(cbSchema)}.callback_states`);
    restoredApp = new PostgresSessionStore({ connectionString, schema: appSchema, namespace, sessionSecret: 'disposable-ops-rotated-session-secret'.repeat(2) });
    assert.equal(await restoredApp.get(cookie), undefined);
    assert.notEqual(await callbacks.claim(state), 'claimed');
    await assert.rejects(userinfo(issuer.ctx, bearer));
    assert.equal(await f.store.resolveManagement(subject.authorization.hash, subject.agent.handle), 'invalid_token');
    assert.equal(await f.store.signupsEver(subject.agent.ownerId, tx.clientId), 1, 'recovery does not erase retained signup accounting');
    assert.equal(await f.store.insertAccessToken({ ...token, hash: 'attempt-after-restore' }, f.now()), false);

    // Returning to an older session secret would undo the recovery. Erase old sessions as an additional fence.
    await f.admin.query(`DELETE FROM ${quote(appSchema)}.app_sessions`);
    oldSecretApp = new PostgresSessionStore({ connectionString, schema: appSchema, namespace, sessionSecret: secret });
    assert.equal(await oldSecretApp.get(cookie), undefined);
    // Synthetic newly authenticated session: this checks retained data, not new human approval.
    const fresh = sid();
    assert.equal((await restoredApp.create(fresh, appSession)).firstSeen, original.firstSeen);
    assert.equal((await restoredApp.listNotes(fresh))?.[0]?.id, 'restore-rehearsal-note');
    await evidence('restore', { passed: true, actualPgDumpRestore: true, restoredRevocationRegressionDemonstrated: true, issuerAuthorityQuarantined: true, ownerCredentialRemoved: true, callbackStatePurged: true, applicationSecretRotated: true, oldSessionsPurged: true, retainedNotesAndCountsPreserved: true, productionRecoveryRehearsed: false, limitation: 'Only synthetic known identities are reconciled. Unknown post-backup deletions, consent, counts, mail ownership and passkey generation require separate authoritative recovery before reopening.' });
  } finally {
    await Promise.all([app.close(), callbacks.close(), restoredApp?.close(), oldSecretApp?.close()]);
    await f.admin.query(`DROP SCHEMA IF EXISTS ${quote(appSchema)},${quote(cbSchema)} CASCADE`);
  }
});

test('PostgreSQL signing rotation publishes before activation and emergency withdrawal fences a stale replica', options, async (t) => {
  localUrl();
  const f = await fixture(t);
  const firstPair = await generateKeyPair('ES256', { extractable: true });
  const secondPair = await generateKeyPair('ES256', { extractable: true });
  const first = await exportJWK(firstPair.privateKey), second = await exportJWK(secondPair.privateKey);
  const opts = { issuer: 'https://issuer.example', handleDomains: ['example.com'], now: f.now, signingJwk: first, jwksCacheSeconds: 10 };
  const a = await createIssuer({ ...opts, store: f.store }), b = await createIssuer({ ...opts, store: f.peer });
  const { agent } = await prepareAgent(f.store, f.now(), 'rotation');
  const owner = (await f.store.getOwner(agent.ownerId))!;
  const client = { clientId: 'rotation-client', type: 'open' as const, redirectUris: ['https://rp.example/cb'], requireReview: false, tokenEndpointAuthMethod: 'none' as const };
  const claims = { agent, owner, client, scopes: ['openid'] as ['openid'], nonce: 'rotation-nonce', authTime: f.now() };
  const original = await mintIdToken(a.ctx, claims);
  const [kid] = await a.publishSigningKeys([second]);
  assert.ok((await (await b.app.request('/.well-known/jwks.json')).json()).keys.some((key: {kid: string}) => key.kid === kid));
  assert.equal(await a.activateSigningKey(kid!), false);
  await f.advance(1);
  assert.equal(await a.activateSigningKey(kid!), true);
  await assert.rejects(mintIdToken(b.ctx, claims), /No active/);
  await b.publishSigningKeys([second]);
  assert.equal(decodeProtectedHeader(await mintIdToken(b.ctx, claims)).kid, kid);
  await jwtVerify(original, firstPair.publicKey, { issuer: opts.issuer, audience: client.clientId, currentDate: new Date(f.now() * 1000) });
  assert.equal(await a.removeSigningKey(decodeProtectedHeader(original).kid!), false);
  assert.equal(await a.removeSigningKey(kid!, true), true);
  await assert.rejects(mintIdToken(b.ctx, claims), /No active/);
  assert.equal((await (await b.app.request('/.well-known/jwks.json')).json()).keys.some((key: {kid: string}) => key.kid === kid), false);
  await evidence('signing-rotation', { passed: true, independentPostgresPools: true, publishBeforeUse: true, routineOverlap: true, staleReplicaFailsClosed: true, emergencyWithdrawal: true, externalCacheInvalidationProven: false });
});

test('complete PostgreSQL outage denies protected reads, writes and logout without losing prior data', options, async (t) => {
  const url = localUrl();
  const f = await fixture(t, { realClock: true });
  const schema = `${f.schema}_app`;
  const store = new PostgresSessionStore({ connectionString, schema, namespace, sessionSecret: secret, connectionTimeoutMs: 500 });
  await store.migrate();
  const cookie = sid();
  await store.create(cookie, session(Math.floor(Date.now() / 1000)));
  await store.saveNote(cookie, 'before-outage-note', 'This write was acknowledged before outage');
  const { app } = createExample({ base: namespace, issuer: 'https://issuer.example', stateSecret: 'disposable-state-secret'.repeat(3), callbackStore: new MemoryCallbackStateStore(), sessionStore: store, ready: async () => { await store.verifySchema(); return true; } });
  const data = join(process.env.AGENTLOGIN_OPS_WORK!, 'data');
  let down = false;
  try {
    await run(bin('pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { timeout: 30_000 }); down = true;
    assert.equal((await app.request(namespace + '/healthz')).status, 200);
    for (const [path, method] of [['/readyz', 'GET'], ['/me', 'GET'], ['/notes', 'POST'], ['/logout', 'POST']]) {
      const result = await app.request(namespace + path, { method, headers: { cookie: `__Host-sid=${cookie}`, 'content-type': 'application/json' }, ...(method === 'POST' ? { body: '{}' } : {}) });
      assert.equal(result.status, 503, path);
      assert.equal(result.headers.get('set-cookie'), null, 'failure cannot acknowledge cookie-only logout');
    }
  } finally {
    if (down) await run(bin('pg_ctl'), ['-D', data, '-l', join(process.env.AGENTLOGIN_OPS_WORK!, 'postgres.log'), '-o', `-h 127.0.0.1 -p ${url.port} -k ${process.env.AGENTLOGIN_OPS_WORK} -c max_connections=80`, '-w', 'start'], { timeout: 30_000 });
    await store.close();
  }
  const recovered = new PostgresSessionStore({ connectionString, schema, namespace, sessionSecret: secret });
  try {
    assert.ok(await recovered.get(cookie));
    assert.equal((await recovered.listNotes(cookie))?.[0]?.id, 'before-outage-note');
    await recovered.revoke(cookie);
    assert.equal(await recovered.get(cookie), undefined);
    await evidence('outage', { passed: true, wholeDatabaseStopped: true, livenessRemainedAvailable: true, readinessAndProtectedOperations503: true, logoutNotAcknowledged: true, acknowledgedDataSurvivedRestart: true });
  } finally { await recovered.close(); await f.admin.query(`DROP SCHEMA ${quote(schema)} CASCADE`); }
});

test('bounded mixed store workload records latency as indexed history grows', { ...options, timeout: 180_000 }, async (t) => {
  localUrl();
  const f = await fixture(t, { realClock: true, maxConnections: 4 });
  const peer = new PostgresStore({ connectionString, schema: f.schema, maxConnections: 4, maxRetries: 12, retryBaseMs: 2 });
  t.after(() => peer.close());
  const stages = [];
  const now = Math.floor(Date.now() / 1000);
  const target = await prepareAgent(f.store, now, 'lookup');
  // Bulk seeding is deliberately outside measurements. Every measured write uses the real Store API.
  for (const records of [100, 1_000, 10_000]) {
    await f.admin.query(`INSERT INTO ${quote(f.schema)}.agents(data) SELECT jsonb_build_object('handle','history-'||n||'@example.com','sub','history-sub-'||n,'local','history-'||n,'domain','example.com','ownerId','owner','preferredUsername','history','enabled',false,'authorizationVersion',1,'createdAt',$2::bigint) FROM generate_series(1,$1::integer) n ON CONFLICT DO NOTHING`, [records, now]);
    await f.admin.query(`ANALYZE ${quote(f.schema)}.agents`);
    const latencies: Record<string, number[]> = { lookup: [], polling: [], admissionAndCompletion: [], revocation: [] };
    const plans = await f.admin.query(`EXPLAIN (FORMAT JSON) SELECT data FROM ${quote(f.schema)}.agents WHERE handle=$1`, [target.agent.handle]);
    for (let warm = 0; warm < 20; warm++) await peer.getAgent(target.agent.handle);
    const start = performance.now();
    await Promise.all(Array.from({ length: 4 }, async (_, worker) => {
      const store = worker % 2 ? peer : f.store;
      for (let iteration = 0; iteration < 25; iteration++) {
        const measure = async <T>(kind: string, fn: () => Promise<T>) => { const at = performance.now(); const value = await fn(); latencies[kind]!.push(performance.now() - at); return value; };
        await measure('lookup', async () => assert.equal((await store.getAgent(target.agent.handle))?.sub, target.agent.sub));
        const id = `load-${records}-${worker}-${iteration}`, ownerId = `owner-${id}`;
        const subject = await prepareAgent(store, now, id, ownerId);
        const tx = await measure('admissionAndCompletion', async () => {
          const started = await begin(store, now, id, `tx-${id}`, 'load-client', undefined, ownerId);
          assert.equal((await store.completeTransaction(started, started.version, codeFor(started, now), now))?.status, 'completed');
          return started;
        });
        for (let poll = 0; poll < 4; poll++) await measure('polling', async () => assert.equal((await store.readTransaction(tx.id, { now, retainFor: 300 }))?.status, 'completed'));
        await measure('revocation', async () => assert.equal((await store.revokeKey(subject.key.kid, subject.key.enrollment, now))?.status, 'revoked'));
      }
    }));
    const elapsedMs = performance.now() - start;
    const stats = Object.fromEntries(Object.entries(latencies).map(([name, values]) => {
      values.sort((a, b) => a - b);
      const p = (fraction: number) => Number(values[Math.ceil(values.length * fraction) - 1]!.toFixed(2));
      return [name, { samples: values.length, p50Ms: p(.5), p95Ms: p(.95), p99Ms: p(.99), maxMs: p(1) }];
    }));
    stages.push({ seededHistoricalAgents: records, actualAgentRows: Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.agents`)).rows[0].count), elapsedMs: Number(elapsedMs.toFixed(2)), operations: stats, lookupPlan: plans.rows[0]['QUERY PLAN'][0].Plan['Node Type'] });
  }
  await evidence('load', { passed: true, scope: 'store-level, closed workload; no HTTP, crypto, public network, or human authentication', admissionAndCompletionIncludes: ['client upsert', 'pending transaction insertion', 'assertion transition and quota admission', 'atomic account/code completion'], concurrentWorkers: 4, storePools: 2, maxConnectionsPerStore: 4, warmupLookupsPerStage: 20, failures: 0, stages, productionCapacityClaim: false });
});
