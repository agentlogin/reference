import { test } from 'node:test';
import assert from 'node:assert/strict';
import { begin, codeFor, deferred, eventually, fixture, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL binds max_age and auth_time to the stored assertion and allows the exact positive boundary', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const startedAt = f.now();
  const transaction = await begin(f.store, startedAt, 'one', 'one', 'client', 1, 'owner', 20);
  await f.advance(3);
  const approved = await f.store.updateTransaction({ ...transaction, maxAge: undefined, assertedAt: f.now() }, transaction.version, { now: f.now() });
  assert.ok(approved);
  assert.equal(approved.maxAge, 20);
  assert.equal(approved.assertedAt, startedAt);
  await f.advance(17);
  const input = { ...codeFor(approved, f.now()), maxAge: 1_000, authTime: f.now() };
  assert.equal((await f.store.completeTransaction({ ...approved, maxAge: 1_000, assertedAt: f.now() }, approved.version, input, f.now()))?.status, 'completed');
  const stored = await f.peer.getCode(input.hash);
  assert.equal(stored?.maxAge, 20);
  assert.equal(stored?.authTime, startedAt);
  assert.equal(await f.store.redeemCode(input.hash, f.now()), 'ok');
  assert.equal(await f.store.insertAccessToken(tokenFor(approved, f.now()), f.now()), true);
  await f.advance(1);
  assert.equal((await f.peer.getAccessToken(`access-${approved.id}`))?.revoked, false, 'age does not retroactively revoke a valid issued token');
});

test('PostgreSQL max_age zero permits delayed delivery but retains the original assertion time', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const startedAt = f.now();
  const transaction = await begin(f.store, startedAt, 'one', 'one', 'client', 1, 'owner', 0);
  await f.advance(100);
  const code = codeFor(transaction, f.now());
  assert.equal((await f.store.completeTransaction(transaction, transaction.version, code, f.now()))?.status, 'completed');
  await f.advance(10);
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  assert.equal(await f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now()), true);
  assert.equal((await f.peer.getCode(code.hash))?.authTime, startedAt);
});

test('PostgreSQL max_age zero does not disable code expiry', options, async (t) => {
  const f = await fixture(t);
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1, 'owner', 0);
  const code = codeFor(transaction, f.now());
  await f.store.completeTransaction(transaction, transaction.version, code, f.now());
  await f.advance(60);
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'expired');
  assert.equal((await f.peer.getCode(code.hash))?.used, false);
});

async function assertDeniedWithoutSignup(f: Awaited<ReturnType<typeof fixture>>) {
  const stored = await f.peer.getTransaction('one');
  assert.equal(stored?.status, 'denied');
  assert.equal(stored?.reason, 'login_required');
  assert.equal(stored?.codeIssued, false);
  assert.equal(await f.peer.getCode('code-one'), undefined);
  assert.equal(await f.peer.getAccount('one@example.com', 'client'), undefined);
  assert.equal(await f.peer.signupsEver('owner', 'client'), 0);
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations WHERE txn_id='one'`)).rows[0].count), 0);
}

for (const blockAt of ['quota', 'account insert'] as const) {
  test(`PostgreSQL max_age expires during the completion ${blockAt} wait without consuming a signup`, options, async (t) => {
    let capture = false;
    const started = deferred<number>();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (capture && event.operation === 'completeTransaction' && event.phase === 'afterBegin') {
        attempts.push(event.attempt);
        started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
      }
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1, 'owner', 5);
    const blocker = await f.admin.connect();
    try {
      await blocker.query('BEGIN');
      if (blockAt === 'quota') await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.quotas WHERE owner_id='owner' AND client_id='client' FOR UPDATE`);
      else await blocker.query(`LOCK TABLE ${quote(f.schema)}.accounts IN SHARE MODE`);
      capture = true;
      const completing = f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now());
      const outcome = completing.then((value) => ({ value }), (error: unknown) => ({ error }));
      const pid = await started.promise;
      await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'completion did not wait for its database lock');
      await f.advance(6);
      await blocker.query('COMMIT');
      const result = await outcome;
      assert.ok('value' in result, String('error' in result ? result.error : ''));
      assert.equal(result.value?.reason, 'login_required');
      assert.deepEqual(attempts, [0], 'a no-op lock holder must not require a serialization failure to enforce time');
      await assertDeniedWithoutSignup(f);
      assert.equal((await f.peer.getTransaction('one'))?.terminalAt, f.now());
    } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  });
}

for (const operation of ['redeemCode', 'insertAccessToken'] as const) {
  test(`PostgreSQL ${operation} rejects max_age elapsed during an implicit write lock wait`, options, async (t) => {
    let capture = false;
    const started = deferred<number>();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (capture && event.operation === operation && event.phase === 'afterBegin') {
        attempts.push(event.attempt);
        started.resolve(Number((await event.client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid));
      }
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1, 'owner', 5);
    const code = codeFor(transaction, f.now());
    await f.store.completeTransaction(transaction, transaction.version, code, f.now());
    if (operation === 'insertAccessToken') assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
    const blocker = await f.admin.connect();
    try {
      await blocker.query('BEGIN');
      if (operation === 'redeemCode') await blocker.query(`SELECT 1 FROM ${quote(f.schema)}.codes WHERE hash=$1 FOR UPDATE`, [code.hash]);
      else await blocker.query(`LOCK TABLE ${quote(f.schema)}.access_tokens IN SHARE MODE`);
      capture = true;
      const writing = operation === 'redeemCode'
        ? f.store.redeemCode(code.hash, f.now())
        : f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now());
      const outcome = writing.then((value) => ({ value }), (error: unknown) => ({ error }));
      const pid = await started.promise;
      await eventually(async () => (await f.admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0]?.wait_event_type === 'Lock', 'issuance did not wait for its database lock');
      await f.advance(6);
      await blocker.query('COMMIT');
      assert.deepEqual(await outcome, { value: operation === 'redeemCode' ? 'expired' : false });
      assert.deepEqual(attempts, [0]);
      assert.equal(await f.peer.getAccessToken(`access-${transaction.id}`), undefined);
      assert.equal((await f.peer.getCode(code.hash))?.used, operation === 'insertAccessToken');
      const marker = (await f.admin.query(`SELECT redemption_attempt FROM ${quote(f.schema)}.codes WHERE hash=$1`, [code.hash])).rows[0].redemption_attempt;
      assert.equal(marker === null, operation === 'redeemCode');
    } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  });
}

for (const operation of ['completeTransaction', 'redeemCode', 'insertAccessToken'] as const) {
  test(`PostgreSQL ${operation} rechecks max_age on a confirmed serialization rollback`, options, async (t) => {
    let capture = false;
    let advance: (() => Promise<void>) | undefined;
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!capture || event.operation !== operation) return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'beforeCommit' && event.attempt === 0) {
        await advance!();
        throw Object.assign(new Error('confirmed serialization rollback after age elapsed'), { code: '40001' });
      }
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1, 'owner', 5);
    const code = codeFor(transaction, f.now());
    const staleNow = f.now();
    if (operation !== 'completeTransaction') await f.store.completeTransaction(transaction, transaction.version, code, f.now());
    if (operation === 'insertAccessToken') await f.store.redeemCode(code.hash, f.now());
    advance = () => f.advance(6);
    capture = true;
    if (operation === 'completeTransaction') {
      assert.equal((await f.store.completeTransaction(transaction, transaction.version, code, staleNow))?.reason, 'login_required');
      await assertDeniedWithoutSignup(f);
    } else if (operation === 'redeemCode') {
      assert.equal(await f.store.redeemCode(code.hash, staleNow), 'expired');
      assert.equal((await f.peer.getCode(code.hash))?.used, false);
    } else {
      assert.equal(await f.store.insertAccessToken(tokenFor(transaction, staleNow), staleNow), false);
      assert.equal(await f.peer.getAccessToken(`access-${transaction.id}`), undefined);
    }
    assert.deepEqual(attempts, [0, 1]);
  });
}

for (const operation of ['completeTransaction', 'redeemCode', 'insertAccessToken'] as const) {
  test(`PostgreSQL ${operation} reconciles a committed result without renewing authentication`, options, async (t) => {
    let capture = false;
    let advance: (() => Promise<void>) | undefined;
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!capture || event.operation !== operation) return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'afterCommit') {
        capture = false;
        await advance!();
        throw new Error('lost acknowledgement after committed valid operation');
      }
    } });
    await prepareAgent(f.store, f.now(), 'one');
    const startedAt = f.now();
    const transaction = await begin(f.store, startedAt, 'one', 'one', 'client', 1, 'owner', 5);
    const code = codeFor(transaction, f.now());
    if (operation !== 'completeTransaction') await f.store.completeTransaction(transaction, transaction.version, code, f.now());
    if (operation === 'insertAccessToken') await f.store.redeemCode(code.hash, f.now());
    advance = () => f.advance(6);
    capture = true;
    if (operation === 'completeTransaction') {
      assert.equal((await f.store.completeTransaction(transaction, transaction.version, code, startedAt))?.status, 'completed');
      assert.equal(await f.store.redeemCode(code.hash, f.now()), 'expired');
      assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
    } else if (operation === 'redeemCode') {
      assert.equal(await f.store.redeemCode(code.hash, startedAt), 'expired');
      assert.equal((await f.peer.getCode(code.hash))?.used, true, 'committed redemption is never released or repeated');
      assert.equal(await f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now()), false);
    } else {
      assert.equal(await f.store.insertAccessToken(tokenFor(transaction, startedAt), startedAt), true, 'token was validly issued before age elapsed');
      assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, false);
    }
    assert.deepEqual(attempts, [0]);
    assert.equal((await f.peer.getCode(code.hash))?.authTime, startedAt);
    assert.notEqual((await f.peer.getCode(code.hash))?.replayed, true);
  });
}
