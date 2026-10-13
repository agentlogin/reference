import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isKeyActivationConflictError } from '../../issuer/src/store.js';
import { asserted, deferred, eventually, fixture, pending, prepareAgent, quote, skipPostgres } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL pending challenges do not reserve a public key and mutations stay enrollment-scoped', options, async (t) => {
  const f = await fixture(t);
  const attacker = await prepareAgent(f.store, f.now(), 'attacker');
  const legitimate = await prepareAgent(f.peer, f.now(), 'legitimate');
  const first = { ...attacker.key, kid: 'shared-key', enrollment: 'unproved-enrollment' };
  const second = { ...legitimate.key, kid: first.kid, enrollment: 'proved-enrollment' };
  assert.equal(await f.store.insertKey(first, f.now(), attacker.authorization), 'ok');
  assert.equal(await f.peer.insertKey(second, f.now(), legitimate.authorization), 'ok');
  assert.equal(await f.store.getKey(first.kid), undefined, 'an unscoped read cannot choose among pending Agents');
  assert.equal(await f.peer.activateKey(second.kid, second.enrollment, 'challenge', f.now()), true);
  assert.equal((await f.store.getKey(first.kid))?.enrollment, second.enrollment);
  assert.equal((await f.store.getKey(first.kid, first.handle))?.status, 'pending');
  await f.store.patchKey(first.kid, first.enrollment, { name: 'Unproved key' });
  assert.equal((await f.peer.getKey(second.kid, second.handle))?.name, undefined);
  await f.store.revokeKey(first.kid, first.enrollment, f.now());
  assert.equal((await f.peer.getKey(second.kid, second.handle))?.status, 'active');
  await f.store.deleteKey(first.kid, first.enrollment);
  assert.equal((await f.peer.getKey(second.kid, second.handle))?.status, 'active');
});

test('PostgreSQL independent activation snapshots produce exactly one active enrollment', options, async (t) => {
  let armed = false;
  const checked = deferred();
  const release = deferred();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && event.operation === 'activateKey' && event.phase === 'activation_checked' && event.attempt === 0) {
      checked.resolve();
      await release.promise;
    }
  } });
  const first = await prepareAgent(f.store, f.now(), 'first');
  const second = await prepareAgent(f.peer, f.now(), 'second');
  const a = { ...first.key, kid: 'shared-key', enrollment: 'first-pending' };
  const b = { ...second.key, kid: a.kid, enrollment: 'second-pending' };
  assert.equal(await f.store.insertKey(a, f.now(), first.authorization), 'ok');
  assert.equal(await f.peer.insertKey(b, f.now(), second.authorization), 'ok');
  armed = true;
  const losing = f.store.activateKey(a.kid, a.enrollment, 'challenge', f.now());
  const outcome = losing.then((value) => ({ value }), (error: unknown) => ({ error }));
  await checked.promise;
  try {
    assert.equal(await f.peer.activateKey(b.kid, b.enrollment, 'challenge', f.now()), true);
  } finally { release.resolve(); }
  const result = await outcome;
  assert.ok('error' in result && isKeyActivationConflictError(result.error), 'the losing proof must fail with the protocol conflict');
  assert.equal((await f.store.getKey(a.kid, a.handle))?.status, 'pending');
  assert.equal((await f.peer.getKey(b.kid, b.handle))?.status, 'active');
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.keys WHERE kid=$1 AND status='active'`, [a.kid])).rows[0].count), 1);
});

test('PostgreSQL activation retires expired proof after a quota wait at its original expiry', options, async (t) => {
  let armed = false;
  const started = deferred<number>();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && event.operation === 'activateKey' && event.phase === 'afterBegin') {
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  const first = await prepareAgent(f.store, f.now(), 'first');
  const second = await prepareAgent(f.peer, f.now(), 'second');
  const a = { ...first.key, kid: 'shared-key', enrollment: 'first-expiring', expiresAt: f.now() + 5 };
  const b = { ...second.key, kid: a.kid, enrollment: 'second-pending' };
  assert.equal(await f.store.insertKey(a, f.now(), first.authorization), 'ok');
  assert.equal(await f.store.activateKey(a.kid, a.enrollment, 'challenge', f.now()), true);
  assert.equal(await f.peer.insertKey(b, f.now(), second.authorization), 'ok');
  const tx = await pending(f.store, f.now(), 'old-enrollment');
  assert.equal((await f.store.updateTransaction({ ...asserted(tx, 'first', f.now()), kid: a.kid, keyEnrollment: a.enrollment }, 0, { now: f.now(), maxSignups: 1 }))?.status, 'ready');
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.quotas WHERE owner_id='owner' AND client_id='client' FOR UPDATE`);
    armed = true;
    const activation = f.store.activateKey(b.kid, b.enrollment, 'challenge', f.now());
    const outcome = activation.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'activation did not wait on the old enrollment quota');
    await f.advance(6);
    await blocker.query('COMMIT');
    assert.deepEqual(await outcome, { value: true });
    assert.equal((await f.peer.getKey(a.kid, a.handle))?.status, 'expired');
    assert.equal((await f.peer.getKey(b.kid, b.handle))?.status, 'active');
    const denied = await f.peer.readTransaction(tx.id, { now: f.now(), retainFor: 300 });
    assert.equal(denied?.status, 'denied');
    assert.equal(denied?.reason, 'key_revoked');
    assert.equal(denied?.terminalAt, a.expiresAt);
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
    assert.equal(await f.store.revokeKey(a.kid, a.enrollment, f.now()), undefined);
    assert.equal((await f.peer.getKey(b.kid, b.handle))?.status, 'active');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL cleanup deletes only an expired challenge sharing an active key thumbprint', options, async (t) => {
  const f = await fixture(t);
  const first = await prepareAgent(f.store, f.now(), 'first');
  const second = await prepareAgent(f.peer, f.now(), 'second');
  const abandoned = { ...first.key, kid: second.key.kid, enrollment: 'abandoned', challenge: { value: 'challenge', expiresAt: f.now() + 5 } };
  assert.equal(await f.store.insertKey(abandoned, f.now(), first.authorization), 'ok');
  await f.advance(6);
  await f.store.cleanup({ batchSize: 1 });
  assert.equal(await f.peer.getKey(abandoned.kid, abandoned.handle), undefined);
  assert.equal((await f.peer.getKey(second.key.kid, second.key.handle))?.status, 'active');
});

test('PostgreSQL conditional pending cleanup uses database time and cannot delete an activated enrollment', options, async (t) => {
  const f = await fixture(t);
  const subject = await prepareAgent(f.store, f.now(), 'owner');
  const key = { ...subject.key, kid: 'pending-key', enrollment: 'pending-cleanup', challenge: { value: 'challenge', expiresAt: f.now() + 5 } };
  assert.equal(await f.store.insertKey(key, f.now(), subject.authorization), 'ok');
  await f.store.deleteKey(key.kid, key.enrollment, f.now() + 500);
  assert.equal((await f.peer.getKey(key.kid, key.handle))?.status, 'pending', 'caller time cannot expire a live challenge');
  await f.advance(6);
  await f.store.deleteKey(key.kid, key.enrollment, f.now() - 500);
  assert.equal(await f.peer.getKey(key.kid, key.handle), undefined, 'database time expires the pending challenge');
  await f.store.deleteKey(subject.key.kid, subject.key.enrollment, f.now() + 500);
  assert.equal((await f.peer.getKey(subject.key.kid, subject.key.handle))?.status, 'active', 'timeout cleanup cannot erase an active enrollment');
});

test('PostgreSQL pending cleanup retries after an in-flight activation and preserves its key', options, async (t) => {
  let armed = false;
  const activated = deferred();
  const release = deferred();
  const cleanupStarted = deferred<number>();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (!armed) return;
    if (event.operation === 'activateKey' && event.phase === 'beforeCommit' && event.attempt === 0) {
      activated.resolve();
      await release.promise;
    }
    if (event.operation === 'deleteKey' && event.phase === 'afterBegin' && event.attempt === 0) {
      cleanupStarted.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'owner');
  const key = { ...subject.key, kid: 'pending-key', enrollment: 'pending-race', challenge: { value: 'challenge', expiresAt: f.now() + 5 } };
  assert.equal(await f.store.insertKey(key, f.now(), subject.authorization), 'ok');
  armed = true;
  const activation = f.store.activateKey(key.kid, key.enrollment, 'challenge', f.now());
  await activated.promise;
  await f.advance(6);
  const cleanup = f.store.deleteKey(key.kid, key.enrollment, f.now());
  const pid = await cleanupStarted.promise;
  try {
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'cleanup did not wait on the in-flight activation');
  } finally { release.resolve(); }
  assert.equal(await activation, true);
  await cleanup;
  assert.equal((await f.peer.getKey(key.kid, key.handle))?.status, 'active');
});
