import { test } from 'node:test';
import assert from 'node:assert/strict';
import { begin, codeFor, deferred, fixture, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL polling projects expiry without writing stored status or extending retention', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
  const before = await f.peer.getTransaction(transaction.id);
  await f.admin.query(`CREATE FUNCTION ${quote(f.schema)}.refuse_write() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''polling attempted to write''; END'`);
  for (const table of ['transactions', 'reservations', 'codes', 'access_tokens']) {
    await f.admin.query(`CREATE TRIGGER polling_must_not_write BEFORE INSERT OR UPDATE OR DELETE ON ${quote(f.schema)}.${quote(table)} FOR EACH STATEMENT EXECUTE FUNCTION ${quote(f.schema)}.refuse_write()`);
  }
  await f.advance(301);
  const expired = await f.store.readTransaction(transaction.id, { now: transaction.createdAt, retainFor: 300 });
  assert.equal(expired?.status, 'expired');
  assert.equal(expired?.terminalAt, transaction.expiresAt);
  assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
  await f.advance(300);
  assert.equal(await f.store.readTransaction(transaction.id, { now: transaction.createdAt, retainFor: 300 }), undefined);
  assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
});

test('PostgreSQL cleanup retains used-code replay evidence while its access token remains live', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
  const code = codeFor(transaction, f.now());
  await f.store.completeTransaction(transaction, transaction.version, code, f.now());
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  assert.equal(await f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now()), true);
  await f.advance(61);
  await f.store.cleanup({ batchSize: 100, retainFor: 300 });
  assert.ok(await f.peer.getCode(code.hash), 'expired authorization code is still required for replay protection');
  assert.equal(await f.peer.redeemCode(code.hash, f.now()), 'used');
  assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, true);
  await f.advance(600);
  await f.store.cleanup({ batchSize: 100, retainFor: 300 });
  assert.equal(await f.peer.getAccessToken(`access-${transaction.id}`), undefined);
  assert.equal(await f.peer.getCode(code.hash), undefined);
  assert.equal(await f.peer.signupsEver('owner', 'client'), 1, 'transient cleanup preserves permanent signup accounting');
});

test('PostgreSQL cleanup cannot erase a revoked-key tombstone', options, async (t) => {
  const f = await fixture(t);
  const subject = await prepareAgent(f.store, f.now(), 'one');
  assert.ok(await f.store.revokeKey(subject.key.kid, subject.key.enrollment, f.now()));
  await f.advance(86_400);
  await f.store.cleanup({ batchSize: 100, retainFor: 300 });
  assert.equal(await f.peer.wasRevoked(subject.agent.handle, subject.key.kid), true);
  const replacement = { ...subject.key, enrollment: 'replacement-enrollment', createdAt: f.now(), expiresAt: f.now() + 300, challenge: { value: 'new-challenge', expiresAt: f.now() + 60 } };
  assert.equal(await f.peer.insertKey(replacement, f.now(), subject.authorization), 'revoked');
});

test('PostgreSQL cleanup preserves explicit revocation evidence for a retained legacy transaction bearer', options, async (t) => {
  const f = await fixture(t);
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one');
  assert.ok(await f.store.revokeKey(subject.key.kid, subject.key.enrollment, f.now()));
  const legacy = { ...transaction, id: 'legacy-retained', status: 'denied' as const, reason: 'cancelled' as const, terminalAt: f.now() };
  await f.store.insertTransaction(legacy);
  const before = await f.peer.getTransaction(legacy.id);
  await f.advance(3_601);
  await f.store.cleanup({ batchSize: 100, retainFor: 7_200 });
  assert.equal((await f.peer.getKey(subject.key.kid, subject.key.handle))?.status, 'revoked', 'the enrollment remains the authority source while any transaction retains it');
  const retained = await f.peer.readTransaction(legacy.id, { now: f.now(), retainFor: 7_200 });
  assert.equal(retained?.transactionTokenHash, undefined);
  assert.equal(retained?.status, legacy.status);
  assert.equal(retained?.terminalAt, legacy.terminalAt);
  assert.deepEqual(await f.peer.getTransaction(legacy.id), before, 'cleanup neither changes the retained outcome nor restarts retention');
});

test('PostgreSQL cleanup cannot delete the code behind a concurrently issued token', options, async (t) => {
  let armed = false;
  const inserted = deferred();
  const cleanupBegan = deferred();
  const release = deferred();
  const f = await fixture(t, { issuanceWindowSeconds: 120, async onCheckpoint(event) {
    if (!armed) return;
    if (event.operation === 'insertAccessToken' && event.phase === 'beforeCommit' && event.attempt === 0) {
      inserted.resolve();
      await release.promise;
    }
    if (event.operation === 'cleanup' && event.phase === 'afterBegin') cleanupBegan.resolve();
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one');
  const code = codeFor(transaction, f.now());
  await f.store.completeTransaction(transaction, transaction.version, code, f.now());
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  await f.advance(61);
  armed = true;
  const issuance = f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now());
  await inserted.promise;
  // The code is now eligible for collection unless the uncommitted token's
  // dependency prevents deletion. The issuance was accepted within its window.
  await f.advance(60);
  const cleanup = f.store.cleanup({ batchSize: 100, retainFor: 300 });
  await cleanupBegan.promise;
  release.resolve();
  assert.equal(await issuance, true);
  await cleanup;
  assert.ok(await f.peer.getCode(code.hash));
  assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, false);
  assert.equal(await f.peer.redeemCode(code.hash, f.now()), 'used');
  assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, true);
});
