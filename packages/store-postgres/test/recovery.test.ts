import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { UncertainCommitError } from '../src/runtime.js';
import { asserted, begin, codeFor, connectionString, deferred, eventually, fixture, pending, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL reconciles lost commit acknowledgements by enrollment, code, redemption attempt and token hash', options, async (t) => {
  let loseAcknowledgementFor: string | undefined;
  const lost: string[] = [];
  const f = await fixture(t, { onCheckpoint(event) {
    if (event.operation === loseAcknowledgementFor && event.phase === 'afterCommit') {
      lost.push(event.operation);
      loseAcknowledgementFor = undefined;
      throw new Error('injected connection loss after committed mutation');
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'one');
  const enrollment = { ...subject.key, kid: 'fresh-key', enrollment: 'fresh-enrollment' };
  loseAcknowledgementFor = 'insertKey';
  assert.equal(await f.store.insertKey(enrollment, f.now(), subject.authorization), 'ok');
  assert.equal((await f.peer.getKey(enrollment.kid))?.enrollment, enrollment.enrollment);

  const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
  const code = codeFor(transaction, f.now());
  loseAcknowledgementFor = 'completeTransaction';
  assert.equal((await f.store.completeTransaction(transaction, transaction.version, code, f.now()))?.status, 'completed');
  assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
  assert.equal((await f.peer.getAccount('one@example.com', 'client'))?.signInCount, 1);
  loseAcknowledgementFor = 'redeemCode';
  assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
  assert.notEqual((await f.peer.getCode(code.hash))?.replayed, true);
  const marker = await f.admin.query(`SELECT redemption_attempt, redeemed_at, issuance_until FROM ${quote(f.schema)}.codes WHERE hash = $1`, [code.hash]);
  assert.equal(typeof marker.rows[0].redemption_attempt, 'string');
  assert.ok(Number(marker.rows[0].issuance_until) > Number(marker.rows[0].redeemed_at));
  loseAcknowledgementFor = 'insertAccessToken';
  assert.equal(await f.store.insertAccessToken(tokenFor(transaction, f.now()), f.now()), true);
  assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, false);

  // A separate HTTP redemption attempt must remain a replay, even after internal recovery succeeded.
  assert.equal(await f.peer.redeemCode(code.hash, f.now()), 'used');
  assert.equal((await f.peer.getAccessToken(`access-${transaction.id}`))?.revoked, true);
  assert.deepEqual(lost, ['insertKey', 'completeTransaction', 'redeemCode', 'insertAccessToken']);
});

test('PostgreSQL destructive owner-code consumption fails closed after an uncertain commit', options, async (t) => {
  let attempts = 0;
  const f = await fixture(t, { onCheckpoint(event) {
    if (event.operation !== 'takeOwnerCode') return;
    if (event.phase === 'afterBegin') attempts += 1;
    if (event.phase === 'afterCommit') throw new Error('lost owner-code response');
  } });
  await f.store.putOwnerCode({ ownerId: 'owner', hash: 'one-time-code', expiresAt: f.now() + 60 });
  await assert.rejects(f.store.takeOwnerCode('owner'), (error: unknown) => error instanceof UncertainCommitError && error.operation === 'takeOwnerCode');
  assert.equal(attempts, 1, 'an uncertain destructive operation is never retried');
  assert.equal(await f.peer.takeOwnerCode('owner'), undefined, 'the committed consumption stays consumed');
});

test('PostgreSQL reconciles one accepted assertion after its commit acknowledgement is lost', options, async (t) => {
  const attempts: number[] = [];
  const f = await fixture(t, { onCheckpoint(event) {
    if (event.operation !== 'updateTransaction') return;
    if (event.phase === 'afterBegin') attempts.push(event.attempt);
    if (event.phase === 'afterCommit') throw new Error('lost assertion acknowledgement');
  } });
  await prepareAgent(f.store, f.now(), 'one');
  const transaction = await pending(f.store, f.now(), 'assertion-ack');
  const accepted = await f.store.updateTransaction({ ...asserted(transaction, 'one', f.now()), transactionTokenHash: 'accepted-bearer' }, 0, {
    now: f.now(), maxSignups: 1,
    consent: { handle: 'one@example.com', clientId: 'client', scopes: ['openid'], redirectHost: 'rp.example' },
  });
  assert.equal(accepted?.status, 'ready');
  assert.equal(accepted?.transactionTokenHash, 'accepted-bearer');
  assert.deepEqual(attempts, [0], 'reconciliation must not replay assertion effects');
  assert.equal(Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count), 1);
  assert.equal((await f.peer.getConsent('one@example.com', 'client'))?.lastUsedAt, f.now());
});

for (const operation of ['updateTransaction', 'completeTransaction'] as const) {
  test(`PostgreSQL cannot reconcile ${operation} as a bearer success after concurrent revocation`, options, async (t) => {
    let revoke: (() => Promise<void>) | undefined;
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!revoke || event.operation !== operation) return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'afterCommit') {
        await revoke();
        throw new Error('lost acknowledgement after key revocation');
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', `revoked-ack-${operation}`, 'client', 1);
    revoke = async () => { assert.ok(await f.peer.revokeKey(subject.key.kid, subject.key.enrollment, f.now())); };
    const mutation = operation === 'updateTransaction'
      ? f.store.updateTransaction({ ...transaction, status: 'denied', reason: 'cancelled' }, transaction.version, { now: f.now(), transactionTokenHash: transaction.transactionTokenHash })
      : f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now(), transaction.transactionTokenHash);
    await assert.rejects(mutation, (error: unknown) => error instanceof UncertainCommitError && error.operation === operation);
    assert.deepEqual(attempts, [0], 'uncertain committed transitions are never retried');
    const stored = await f.peer.getTransaction(transaction.id);
    assert.equal(stored?.transactionTokenHash, undefined);
    assert.equal(stored?.status, operation === 'completeTransaction' ? 'completed' : 'denied');
    assert.equal(stored?.terminalAt, f.now());
    assert.equal(await f.peer.signupsEver('owner', 'client'), operation === 'completeTransaction' ? 1 : 0);
  });
}

for (const phase of ['beforeCommit', 'afterCommit']) {
  test(`PostgreSQL process death ${phase} preserves an atomic completion`, options, async (t) => {
    const f = await fixture(t);
    await prepareAgent(f.store, f.now(), 'one');
    const transaction = await begin(f.store, f.now(), 'one', 'one', 'client', 1);
    const program = `
      import { PostgresStore } from ${JSON.stringify(new URL('../src/postgres-store.ts', import.meta.url).href)};
      import { codeFor } from ${JSON.stringify(new URL('./helpers.ts', import.meta.url).href)};
      const store = new PostgresStore({ connectionString: process.env.AGENTLOGIN_TEST_POSTGRES_URL, schema: process.argv[1],
        onCheckpoint: async (event) => {
          if (event.operation === 'completeTransaction' && event.phase === process.argv[2]) {
            process.send('at-checkpoint');
            await new Promise(() => {});
          }
        }
      });
      const transaction = await store.getTransaction('one');
      await store.completeTransaction(transaction, transaction.version, codeFor(transaction, Number(process.argv[3])), Number(process.argv[3]));
    `;
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', program, f.schema, phase, String(f.now())], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { ...process.env, AGENTLOGIN_TEST_POSTGRES_URL: connectionString } });
    let stderr = '';
    child.stderr!.on('data', (chunk) => { stderr += chunk; });
    const reached = deferred();
    child.on('message', (message) => { if (message === 'at-checkpoint') reached.resolve(); });
    child.once('error', (error) => reached.reject(error));
    const exited = once(child, 'exit');
    void exited.then(([code]) => { if (code !== null) reached.reject(new Error(`worker exited before checkpoint: ${code}: ${stderr}`)); });
    t.after(() => { if (child.exitCode === null && !child.killed) child.kill('SIGKILL'); });
    await reached.promise;
    child.kill('SIGKILL');
    const [, signal] = await exited;
    assert.equal(signal, 'SIGKILL');
    const expected = phase === 'afterCommit' ? 'completed' : 'ready';
    await eventually(async () => (await f.peer.getTransaction(transaction.id))?.status === expected, `state did not settle to ${expected}`);
    assert.equal(await f.peer.signupsEver('owner', 'client'), phase === 'afterCommit' ? 1 : 0);
    assert.equal((await f.peer.getAccount('one@example.com', 'client'))?.signInCount, phase === 'afterCommit' ? 1 : undefined);
    assert.equal((await f.peer.getCode('code-one'))?.used, phase === 'afterCommit' ? false : undefined);
    const reservations = Number((await f.admin.query(`SELECT count(*) FROM ${quote(f.schema)}.reservations`)).rows[0].count);
    assert.equal(reservations, phase === 'afterCommit' ? 0 : 1);
    if (phase === 'beforeCommit') {
      assert.equal((await f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now()))?.status, 'completed');
      assert.equal(await f.peer.signupsEver('owner', 'client'), 1);
    }
  });
}
