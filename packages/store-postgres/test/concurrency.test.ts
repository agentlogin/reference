import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { isAssertionSubjectError, isTransactionExpiredError, isTransactionTokenError } from '../../issuer/src/store.js';
import { asserted, begin, codeFor, connectionString, deferred, eventually, fixture, pending, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL detects an actual serializable write skew and reruns its decision', options, async (t) => {
  const f = await fixture(t);
  for (const id of ['one', 'two']) await f.store.putOwner({ id, ownerSub: `sub-${id}`, email: `${id}@example.com`, emailVerified: false, verifiedVia: 'passkey', createdAt: f.now() });
  let firstReads = 0;
  let retries = 0;
  const bothRead = deferred();
  const promote = (store: typeof f.store, id: string) => store.db.mutate('serializable-write-skew', async (session) => {
    const rows = await session.query(`SELECT data FROM ${session.table('owners')} WHERE id IN ('one', 'two') ORDER BY id`);
    if (session.attempt === 0) {
      if (++firstReads === 2) bothRead.resolve();
      await bothRead.promise;
    } else retries += 1;
    if (rows.rows.some((row) => row.data.emailVerified)) return false;
    await session.query(`UPDATE ${session.table('owners')} SET data = jsonb_set(data, '{emailVerified}', 'true') WHERE id = $1`, [id]);
    return true;
  });
  const results = await Promise.all([promote(f.store, 'one'), promote(f.peer, 'two')]);
  assert.equal(results.filter(Boolean).length, 1);
  assert.ok(retries >= 1, 'the conflicting transaction must re-run its read and decision after rollback');
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.owners WHERE data->>'emailVerified' = 'true'`)).rows[0].count), 1);
});

test('PostgreSQL connections serialize first-signup admission when no account exists', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  await prepareAgent(f.peer, f.now(), 'two');
  const transactions = await Promise.all([
    pending(f.store, f.now(), 'one'), pending(f.peer, f.now(), 'two'),
  ]);
  const results = await Promise.all(transactions.map((transaction, i) => (i ? f.peer : f.store).updateTransaction(
    asserted(transaction, i ? 'two' : 'one', f.now()), 0, { now: f.now(), maxSignups: 1 },
  )));
  assert.equal(results.filter((result) => result?.status === 'ready').length, 1);
  assert.equal(results.filter((result) => result?.reason === 'signup_limit_reached').length, 1);
  const winner = results.find((result) => result?.status === 'ready')!;
  assert.equal((await f.store.completeTransaction(winner, winner.version, codeFor(winner, f.now()), f.now()))?.status, 'completed');
  assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
});

test('PostgreSQL duplicate completion creates one account, one count and one code', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
  const code = codeFor(transaction, f.now());
  const results = await Promise.all([
    f.store.completeTransaction(transaction, transaction.version, code, f.now()),
    f.peer.completeTransaction(transaction, transaction.version, { ...code, hash: 'independent-code' }, f.now()),
  ]);
  assert.equal(results.filter((result) => result?.status === 'completed').length, 1);
  assert.equal((await f.store.getAccount('one@example.com', 'client'))?.signInCount, 1);
  assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.codes`)).rows[0].count), 1);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
});

test('PostgreSQL enrollment cannot commit across handle deletion and ownership reassignment', options, async (t) => {
  let armed = false;
  let stopped = false;
  const insertionReady = deferred();
  const release = deferred();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && !stopped && event.operation === 'insertKey' && event.phase === 'beforeCommit') {
      stopped = true;
      insertionReady.resolve();
      await release.promise;
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const key = { ...subject.key, kid: 'in-flight-key', enrollment: 'in-flight-enrollment' };
  armed = true;
  const inserting = f.store.insertKey(key, f.now(), subject.authorization);
  const outcome = inserting.then((result) => ({ result }), (error: unknown) => ({ error }));
  await insertionReady.promise;
  try {
    assert.equal(await f.peer.deleteAgent(subject.agent.handle, subject.agent.sub, f.now()), true);
    await f.peer.putOwner({ id: 'replacement-owner', ownerSub: 'replacement-owner-sub', email: 'replacement@example.com', emailVerified: true, verifiedVia: 'passkey', createdAt: f.now() });
    assert.equal(await f.peer.putAgent({ ...subject.agent, sub: 'replacement-identity', ownerId: 'replacement-owner' }), true);
  } finally { release.resolve(); }
  const result = await outcome;
  assert.deepEqual(result, { result: 'unauthorized' });
  assert.equal(await f.peer.getKey(key.kid), undefined);
  assert.equal((await f.peer.getAgent(subject.agent.handle))?.sub, 'replacement-identity');
});

for (const sqlState of ['40001', '40P01']) {
  test(`PostgreSQL ${sqlState} retries the whole completion after rolling back every effect`, options, async (t) => {
    const attempts: number[] = [];
    const f = await fixture(t, { onCheckpoint(event) {
      if (event.operation !== 'completeTransaction') return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'beforeCommit' && event.attempt === 0) throw Object.assign(new Error('injected confirmed rollback'), { code: sqlState });
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
    assert.equal((await f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now()))?.status, 'completed');
    assert.deepEqual(attempts, [0, 1]);
    assert.equal((await f.peer.getAccount('one@example.com', 'client'))?.signInCount, 1);
    assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.codes`)).rows[0].count), 1);
  });
}

test('PostgreSQL rechecks assertion expiry after a quota lock wait using fresh database time', options, async (t) => {
  let capture = false;
  const started = deferred<number>();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (capture && event.operation === 'updateTransaction' && event.phase === 'afterBegin') {
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'one');
  await f.admin.query(`INSERT INTO ${quote(f.schema)}.quotas (owner_id, client_id) VALUES ('owner', 'client')`);
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.quotas WHERE owner_id = 'owner' AND client_id = 'client' FOR UPDATE`);
    capture = true;
    const startTime = f.now();
    const completion = f.store.updateTransaction(asserted(transaction, 'one', startTime), 0, {
      now: startTime, maxSignups: 1, assertionWindow: { notBefore: startTime - 1, expiresAt: startTime + 5 },
    });
    const outcome = completion.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1', [pid])).rows[0]?.wait_event_type === 'Lock', 'assertion never waited for the quota lock');
    await f.advance(6);
    await blocker.query('COMMIT');
    const result = await outcome;
    assert.ok('error' in result, 'the assertion must expire while waiting');
    assert.match(String(result.error), /assertion|expir/i);
    assert.equal((await f.peer.getTransaction(transaction.id))?.status, 'awaiting_agent');
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL rejects an assertion at the transaction deadline after a quota lock wait without accepting its identity', options, async (t) => {
  let capture = false;
  const started = deferred<number>();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (capture && event.operation === 'updateTransaction' && event.phase === 'afterBegin') {
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'deadline', 'client', 5);
  const before = await f.peer.getTransaction(transaction.id);
  await f.admin.query(`INSERT INTO ${quote(f.schema)}.quotas (owner_id, client_id) VALUES ('owner', 'client')`);
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.quotas WHERE owner_id='owner' AND client_id='client' FOR UPDATE`);
    capture = true;
    const startTime = f.now();
    const mutation = f.store.updateTransaction({ ...asserted(transaction, 'one', startTime), transactionTokenHash: 'new-assertion-bearer' }, 0, {
      now: startTime, maxSignups: 1, assertionWindow: { notBefore: startTime - 1, expiresAt: startTime + 5 },
      consent: { handle: 'one@example.com', clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
    });
    const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'assertion did not wait on quota');
    await f.advance(5);
    await blocker.query('COMMIT');
    const result = await outcome;
    assert.ok('error' in result && isTransactionExpiredError(result.error), 'transaction expiry takes precedence over signed-assertion expiry');
    assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
    assert.equal((await f.peer.readTransaction(transaction.id, { now: startTime, retainFor: 300 }))?.status, 'expired');
    assert.equal(await f.peer.getConsent('one@example.com', 'client'), undefined);
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

for (const status of ['ready', 'denied', 'awaiting_owner'] as const) {
  test(`PostgreSQL rolls back a ${status} assertion that reaches its deadline during an implicit transaction-row lock wait`, options, async (t) => {
    let capture = false;
    const started = deferred<number>();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (capture && event.operation === 'updateTransaction' && event.phase === 'afterBegin') {
        attempts.push(event.attempt);
        started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
      }
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await pending(f.store, f.now(), `deadline-${status}`, 'client', 5);
    const before = await f.peer.getTransaction(transaction.id);
    const blocker = await f.admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.transactions WHERE id=$1 FOR UPDATE`, [transaction.id]);
      capture = true;
      const startTime = f.now();
      const proposed = { ...asserted(transaction, 'one', startTime), status, transactionTokenHash: 'new-assertion-bearer',
        expiresAt: status === 'awaiting_owner' ? startTime + 600 : transaction.expiresAt,
        reason: status === 'denied' ? 'consent_required' as const : undefined };
      const mutation = f.store.updateTransaction(proposed, 0, { now: startTime, maxSignups: 1,
        assertionWindow: { notBefore: startTime - 1, expiresAt: startTime + 100 },
        consent: { handle: 'one@example.com', clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
      });
      const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
      const pid = await started.promise;
      await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'assertion did not reach its implicit row-lock wait');
      await f.advance(5);
      await blocker.query('COMMIT');
      const result = await outcome;
      assert.ok('error' in result && isTransactionExpiredError(result.error), 'the original transaction deadline must reject even a terminal outcome or proposed extension');
      assert.deepEqual(attempts, [0], 'the final deadline check must not depend on a serialization retry');
      assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
      assert.equal(await f.peer.getConsent('one@example.com', 'client'), undefined);
      assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
    } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  });
}

test('PostgreSQL retry after the transaction deadline rolls back assertion authority, capacity and consent', options, async (t) => {
  let advance: (() => Promise<void>) | undefined;
  const attempts: number[] = [];
  const f = await fixture(t, { async onCheckpoint(event) {
    if (event.operation !== 'updateTransaction') return;
    if (event.phase === 'afterBegin') attempts.push(event.attempt);
    if (event.phase === 'beforeCommit' && event.attempt === 0) {
      await advance!();
      throw Object.assign(new Error('retry at transaction deadline'), { code: '40001' });
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'retry-deadline', 'client', 5);
  const before = await f.peer.getTransaction(transaction.id);
  const startTime = f.now();
  advance = () => f.advance(5);
  await assert.rejects(f.store.updateTransaction({ ...asserted(transaction, 'one', startTime), transactionTokenHash: 'new-assertion-bearer' }, 0, {
    now: startTime, maxSignups: 1, assertionWindow: { notBefore: startTime - 1, expiresAt: startTime + 100 },
    consent: { handle: 'one@example.com', clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
  }), isTransactionExpiredError);
  assert.deepEqual(attempts, [0, 1]);
  assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
  assert.equal(await f.peer.getConsent('one@example.com', 'client'), undefined);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
});

for (const operation of ['updateTransaction', 'completeTransaction'] as const) {
  test(`PostgreSQL ${operation} retries its stale snapshot after explicit key revocation and rejects the old bearer`, options, async (t) => {
    let armed = false;
    const snapshotTaken = deferred();
    const release = deferred();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!armed || event.operation !== operation) return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'quota_locked' && event.attempt === 0) {
        snapshotTaken.resolve();
        await release.promise;
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', `revoke-${operation}`);
    armed = true;
    const mutation = operation === 'updateTransaction'
      ? f.store.updateTransaction({ ...transaction, status: 'denied', reason: 'cancelled' }, transaction.version, { now: f.now(), transactionTokenHash: transaction.transactionTokenHash })
      : f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now(), transaction.transactionTokenHash);
    const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
    await snapshotTaken.promise;
    try {
      assert.ok(await f.peer.revokeKey(subject.key.kid, subject.key.enrollment, f.now()));
    } finally { release.resolve(); }
    const result = await outcome;
    assert.ok('error' in result && isTransactionTokenError(result.error), 'revoked authority must be checked before stale version and terminal state');
    assert.deepEqual(attempts, [0, 1]);
    const revoked = await f.peer.getTransaction(transaction.id);
    assert.equal(revoked?.status, 'denied');
    assert.equal(revoked?.reason, 'key_revoked');
    assert.equal(revoked?.transactionTokenHash, undefined);
    assert.equal(await f.peer.getCode(`code-${transaction.id}`), undefined);
    assert.equal(await f.peer.getAccount('one@example.com', 'client'), undefined);
    assert.equal(await f.peer.signupsEver('owner', 'client'), 0);
  });
}

for (const lifecycle of ['revoked', 'disabled', 'deleted'] as const) {
  test(`PostgreSQL retries and rejects a first assertion whose subject became ${lifecycle} after its snapshot`, options, async (t) => {
    let armed = false;
    const snapshotTaken = deferred();
    const release = deferred();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!armed || event.operation !== 'updateTransaction') return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'quota_locked' && event.attempt === 0) {
        snapshotTaken.resolve();
        await release.promise;
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'one');
    const transaction = await pending(f.store, f.now(), `assertion-subject-${lifecycle}`);
    const before = await f.peer.getTransaction(transaction.id);
    armed = true;
    const mutation = f.store.updateTransaction({ ...asserted(transaction, 'one', f.now()), transactionTokenHash: 'new-assertion-bearer' }, 0, {
      now: f.now(), maxSignups: 1,
      consent: { handle: subject.agent.handle, clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
    });
    const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
    await snapshotTaken.promise;
    try {
      if (lifecycle === 'revoked') assert.ok(await f.peer.revokeKey(subject.key.kid, subject.key.enrollment, f.now()));
      else if (lifecycle === 'disabled') assert.ok(await f.peer.setAgentEnabled(subject.agent.handle, false, subject.agent.sub, f.now()));
      else assert.equal(await f.peer.deleteAgent(subject.agent.handle, subject.agent.sub, f.now()), true);
    } finally { release.resolve(); }
    const result = await outcome;
    assert.ok('error' in result && isAssertionSubjectError(result.error));
    assert.equal(result.error.error, lifecycle === 'revoked' ? 'key_revoked' : 'unknown_key');
    assert.deepEqual(attempts, [0, 1]);
    assert.deepEqual(await f.peer.getTransaction(transaction.id), before, 'a failed assertion cannot bind identity or consume the challenge');
    assert.equal(await f.peer.getConsent(subject.agent.handle, 'client'), undefined);
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
  });
}

for (const status of ['ready', 'denied'] as const) {
  test(`PostgreSQL rejects a ${status} first assertion whose key expires during its transaction-row lock wait`, options, async (t) => {
    let capture = false;
    const started = deferred<number>();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (capture && event.operation === 'updateTransaction' && event.phase === 'afterBegin') {
        attempts.push(event.attempt);
        started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'one');
    const key = { ...subject.key, kid: 'short-lived-key', enrollment: 'short-lived-enrollment', expiresAt: f.now() + 5 };
    assert.equal(await f.store.insertKey(key, f.now(), subject.authorization), 'ok');
    assert.equal(await f.store.activateKey(key.kid, key.enrollment, key.challenge!.value, f.now()), true);
    const transaction = await pending(f.store, f.now(), `key-deadline-${status}`);
    const before = await f.peer.getTransaction(transaction.id);
    const blocker = await f.admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.transactions WHERE id=$1 FOR UPDATE`, [transaction.id]);
      capture = true;
      const startTime = f.now();
      const mutation = f.store.updateTransaction({ ...asserted(transaction, 'one', startTime), status, kid: key.kid, keyEnrollment: key.enrollment,
        transactionTokenHash: 'new-assertion-bearer', reason: status === 'denied' ? 'consent_required' : undefined }, 0, {
        now: startTime, maxSignups: 1,
        consent: { handle: subject.agent.handle, clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
      });
      const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
      const pid = await started.promise;
      await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'assertion did not reach its implicit row-lock wait');
      await f.advance(5);
      await blocker.query('COMMIT');
      const result = await outcome;
      assert.ok('error' in result && isAssertionSubjectError(result.error));
      assert.equal(result.error.error, 'key_revoked');
      assert.deepEqual(attempts, [0]);
      assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
      assert.equal(await f.peer.getConsent(subject.agent.handle, 'client'), undefined);
      assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
    } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  });
}

for (const scenario of [
  { name: 'true to false', before: true, after: false, prompt: undefined, expected: 'awaiting_owner' },
  { name: 'false to true', before: false, after: true, prompt: undefined, expected: 'ready' },
  { name: 'true to false with prompt=none', before: true, after: false, prompt: 'none' as const, expected: 'denied' },
] as const) {
  test(`PostgreSQL first assertion retries a share_owner change ${scenario.name} before accepting its gates`, options, async (t) => {
    let armed = false;
    const snapshotTaken = deferred();
    const release = deferred();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!armed || event.operation !== 'updateTransaction') return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'quota_locked' && event.attempt === 0) {
        snapshotTaken.resolve();
        await release.promise;
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'one');
    assert.ok(await f.store.patchKey(subject.key.kid, subject.key.enrollment, { shareOwner: scenario.before }, subject.authorization));
    const seed = await pending(f.store, f.now(), 'permission-fixture');
    const transaction = { ...seed, id: 'permission-race', prompt: scenario.prompt, scopes: ['openid', 'owner_profile'] as ('openid' | 'owner_profile')[], transactionTokenHash: undefined };
    await f.store.insertTransaction(transaction);
    const before = await f.peer.getTransaction(transaction.id);
    const planned = { ...asserted(transaction, 'one', f.now()), status: scenario.before ? 'ready' as const : 'awaiting_owner' as const,
      ownerApprovalOutstanding: !scenario.before, expiresAt: scenario.before ? transaction.expiresAt : f.now() + 600, transactionTokenHash: 'accepted-bearer' };
    const consent = { handle: subject.agent.handle, clientId: 'client', scopes: transaction.scopes, redirectHost: 'rp.example' };
    armed = true;
    const mutation = f.store.updateTransaction(planned, 0, { now: f.now(), maxSignups: 1, consent, expectedShareOwner: scenario.before });
    const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
    await snapshotTaken.promise;
    try {
      assert.ok(await f.peer.patchKey(subject.key.kid, subject.key.enrollment, { shareOwner: scenario.after }, subject.authorization));
    } finally { release.resolve(); }
    assert.deepEqual(await outcome, { value: undefined }, 'a stale permission plan must retry without accepting an assertion');
    assert.deepEqual(attempts, [0, 1], 'the locked key read must refresh a snapshot predating a committed permission change');
    assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
    assert.equal(await f.peer.getConsent(subject.agent.handle, 'client'), undefined);
    assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
    armed = false;
    const fresh = { ...planned, status: scenario.expected, ownerApprovalOutstanding: !scenario.after,
      reason: scenario.expected === 'denied' ? 'interaction_required' as const : undefined,
      expiresAt: scenario.expected === 'awaiting_owner' ? f.now() + 600 : transaction.expiresAt };
    const accepted = await f.store.updateTransaction(fresh, 0, { now: f.now(), maxSignups: 1,
      consent: scenario.expected === 'denied' ? undefined : consent, expectedShareOwner: scenario.after });
    assert.equal(accepted?.status, scenario.expected);
    assert.equal(accepted?.ownerApprovalOutstanding, !scenario.after);
    assert.equal(accepted?.expiresAt, fresh.expiresAt);
    assert.equal(accepted?.reason, fresh.reason);
  });
}

test('PostgreSQL transaction expiry wins over a stale share_owner plan after contention', options, async (t) => {
  let armed = false;
  const snapshotTaken = deferred();
  const release = deferred();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && event.operation === 'updateTransaction' && event.phase === 'quota_locked' && event.attempt === 0) {
      snapshotTaken.resolve();
      await release.promise;
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'permission-deadline', 'client', 5);
  const before = await f.peer.getTransaction(transaction.id);
  armed = true;
  const mutation = f.store.updateTransaction({ ...asserted(transaction, 'one', f.now()), status: 'awaiting_owner', expiresAt: f.now() + 600,
    ownerApprovalOutstanding: true, transactionTokenHash: 'new-assertion-bearer' }, 0, { now: f.now(), expectedShareOwner: false, maxSignups: 1 });
  const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
  await snapshotTaken.promise;
  try {
    assert.ok(await f.peer.patchKey(subject.key.kid, subject.key.enrollment, { shareOwner: true }, subject.authorization));
    await f.advance(5);
  } finally { release.resolve(); }
  const result = await outcome;
  assert.ok('error' in result && isTransactionExpiredError(result.error));
  assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
});

test('PostgreSQL checks transaction expiry after its key-permission read lock before returning a gate conflict', options, async (t) => {
  let capture = false;
  const started = deferred<number>();
  const attempts: number[] = [];
  const f = await fixture(t, { async onCheckpoint(event) {
    if (capture && event.operation === 'updateTransaction' && event.phase === 'afterBegin') {
      attempts.push(event.attempt);
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'permission-lock-deadline', 'client', 5);
  const before = await f.peer.getTransaction(transaction.id);
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.keys WHERE enrollment=$1 FOR UPDATE`, [subject.key.enrollment]);
    capture = true;
    const startTime = f.now();
    const mutation = f.store.updateTransaction(asserted(transaction, 'one', startTime), 0, { now: startTime,
      expectedShareOwner: true, assertionWindow: { notBefore: startTime - 1, expiresAt: startTime + 5 } });
    const outcome = mutation.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'assertion did not wait on the key-permission read lock');
    await f.advance(5);
    await blocker.query('COMMIT');
    const result = await outcome;
    assert.ok('error' in result && isTransactionExpiredError(result.error));
    assert.deepEqual(attempts, [0], 'fresh expiry does not depend on a database serialization failure');
    assert.deepEqual(await f.peer.getTransaction(transaction.id), before);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL fresh expiry after retry rolls back the first completion and releases the expired reservation', options, async (t) => {
  let advance: (() => Promise<void>) | undefined;
  const f = await fixture(t, { async onCheckpoint(event) {
    if (event.operation === 'completeTransaction' && event.phase === 'beforeCommit' && event.attempt === 0) {
      await advance!();
      throw Object.assign(new Error('retry after transaction expiry'), { code: '40001' });
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
  const staleNow = f.now();
  advance = () => f.advance(301);
  const result = await f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, staleNow), staleNow);
  assert.equal(result?.status, 'expired');
  assert.equal(await f.peer.getCode(`code-${transaction.id}`), undefined);
  assert.equal(await f.peer.getAccount('one@example.com', 'client'), undefined);
  assert.equal(await f.peer.signupsEver('owner', 'client'), 0);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 0);
});

test('PostgreSQL rechecks signed proof time after an implicit key-row lock wait without a serialization retry', options, async (t) => {
  let capture = false;
  const started = deferred<number>();
  const attempts: number[] = [];
  const f = await fixture(t, { async onCheckpoint(event) {
    if (capture && event.operation === 'activateKey' && event.phase === 'afterBegin') {
      attempts.push(event.attempt);
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const key = { ...subject.key, kid: 'pending-key', enrollment: 'pending-enrollment' };
  assert.equal(await f.store.insertKey(key, f.now(), subject.authorization), 'ok');
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.keys WHERE kid = $1 FOR UPDATE`, [key.kid]);
    capture = true;
    const startTime = f.now();
    const activation = f.store.activateKey(key.kid, key.enrollment, key.challenge!.value, startTime, { notBefore: startTime - 1, expiresAt: startTime + 5 });
    const outcome = activation.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1', [pid])).rows[0]?.wait_event_type === 'Lock', 'activation never reached its implicit row-lock wait');
    await f.advance(6);
    // The blocker changes no data. PostgreSQL must not be relied on to raise 40001 here.
    await blocker.query('COMMIT');
    const result = await outcome;
    assert.ok('error' in result, 'the signed proof must expire while waiting');
    assert.match(String(result.error), /assertion|expir|proof/i);
    assert.deepEqual(attempts, [0]);
    assert.equal((await f.peer.getKey(key.kid))?.status, 'pending');
    assert.equal((await f.peer.getKey(key.kid))?.challenge?.value, key.challenge!.value);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL rechecks code expiry after an implicit row-lock wait without consuming the code', options, async (t) => {
  let capture = false;
  const started = deferred<number>();
  const attempts: number[] = [];
  const f = await fixture(t, { async onCheckpoint(event) {
    if (capture && event.operation === 'redeemCode' && event.phase === 'afterBegin') {
      attempts.push(event.attempt);
      started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one');
  const code = codeFor(transaction, f.now());
  await f.store.completeTransaction(transaction, transaction.version, code, f.now());
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.codes WHERE hash = $1 FOR UPDATE`, [code.hash]);
    capture = true;
    const redemption = f.store.redeemCode(code.hash, f.now());
    const outcome = redemption.then((value) => ({ value }), (error: unknown) => ({ error }));
    const pid = await started.promise;
    await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1', [pid])).rows[0]?.wait_event_type === 'Lock', 'redemption never reached its implicit row-lock wait');
    await f.advance(61);
    await blocker.query('COMMIT');
    assert.deepEqual(await outcome, { value: 'expired' });
    assert.deepEqual(attempts, [0]);
    assert.equal((await f.peer.getCode(code.hash))?.used, false);
    const marker = await f.admin.query(`SELECT redemption_attempt FROM ${quote(f.schema)}.codes WHERE hash = $1`, [code.hash]);
    assert.equal(marker.rows[0].redemption_attempt, null);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL unrelated quota pairs progress while one pair is locked', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'busy', 'busy-owner');
  await prepareAgent(f.peer, f.now(), 'free', 'free-owner');
  await f.admin.query(`INSERT INTO ${quote(f.schema)}.quotas (owner_id, client_id) VALUES ('busy-owner', 'client')`);
  const blocker = await f.admin.connect();
  try {
    await blocker.query('BEGIN');
    await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.quotas WHERE owner_id = 'busy-owner' AND client_id = 'client' FOR UPDATE`);
    // statement_timeout makes the claim executable: a global coordination lock would fail this test.
    const independent = await begin(f.peer, f.now(), 'free', 'free', 'client', 1, 'free-owner');
    assert.equal(independent.status, 'ready');
    assert.equal((await f.peer.completeTransaction(independent, independent.version, codeFor(independent, f.now()), f.now()))?.status, 'completed');
    assert.equal(await f.peer.signupsEver('free-owner', 'client'), 1);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('PostgreSQL disable interleaved inside issuance cannot revive the credential after re-enable', options, async (t) => {
  let armed = false;
  let stopped = false;
  const atCommit = deferred();
  const disableBegun = deferred();
  const release = deferred();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && event.operation === 'setAgentEnabled' && event.phase === 'afterBegin') disableBegun.resolve();
    if (armed && !stopped && event.operation === 'insertAccessToken' && event.phase === 'beforeCommit') {
      stopped = true;
      atCommit.resolve();
      await release.promise;
    }
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one');
  const code = codeFor(transaction, f.now());
  await f.store.completeTransaction(transaction, transaction.version, code, f.now());
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  armed = true;
  const issuing = f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now());
  const issuingOutcome = issuing.then((value) => ({ value }), (error: unknown) => ({ error }));
  await atCommit.promise;
  const disabling = f.store.setAgentEnabled('one@example.com', false, 'sub-one', f.now());
  // Disable may wait for issuance locks; release issuance without imposing a false lock-order requirement.
  await disableBegun.promise;
  release.resolve();
  await disabling;
  await issuingOutcome;
  await f.peer.setAgentEnabled('one@example.com', true, 'sub-one', f.now());
  const token = await f.peer.getAccessToken(`access-${transaction.id}`);
  assert.ok(!token || token.revoked || token.agentVersion !== (await f.peer.getAgent('one@example.com'))?.authorizationVersion);
  assert.equal(await f.peer.insertAccessToken({ ...tokenFor(transaction, f.now()), hash: 'late-token' }, f.now()), false);
});

test('PostgreSQL independent processes cannot exceed one signup place', options, async (t) => {
  const f = await fixture(t);
  for (const id of ['one', 'two', 'three']) await prepareAgent(f.store, f.now(), id);
  const code = `
    import { PostgresStore } from ${JSON.stringify(new URL('../src/postgres-store.ts', import.meta.url).href)};
    import { begin, codeFor } from ${JSON.stringify(new URL('./helpers.ts', import.meta.url).href)};
    const store = new PostgresStore({ connectionString: process.env.AGENTLOGIN_TEST_POSTGRES_URL, schema: process.argv[1], maxRetries: 15, retryBaseMs: 2 });
    process.send('ready');
    process.once('message', async () => {
      try {
        const transaction = await begin(store, Number(process.argv[3]), process.argv[2], process.argv[2], 'client', 1);
        const admitted = transaction.status === 'ready';
        if (admitted) await store.completeTransaction(transaction, transaction.version, codeFor(transaction, Number(process.argv[3])), Number(process.argv[3]));
        await store.close();
        process.send({ admitted });
        process.disconnect();
      } catch (error) { console.error(error); process.exit(1); }
    });
  `;
  const workers = ['one', 'two', 'three'].map((id) => {
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', code, f.schema, id, String(f.now())], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { ...process.env, AGENTLOGIN_TEST_POSTGRES_URL: connectionString } });
    let stderr = '';
    let admitted = false;
    child.stderr!.on('data', (chunk) => { stderr += chunk; });
    const ready = deferred();
    child.on('message', (message) => { if (message === 'ready') ready.resolve(); else if (message && typeof message === 'object' && 'admitted' in message) admitted = message.admitted === true; });
    const finished = once(child, 'exit').then(([status]) => { assert.equal(status, 0, stderr); return admitted; });
    void finished.catch((error) => ready.reject(error));
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    return { child, ready: ready.promise, finished };
  });
  await Promise.all(workers.map((worker) => worker.ready));
  for (const worker of workers) worker.child.send('go');
  assert.equal((await Promise.all(workers.map((worker) => worker.finished))).filter(Boolean).length, 1);
  assert.equal(await f.store.signupsEver('owner', 'client'), 1);
});
