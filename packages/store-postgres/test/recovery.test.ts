import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { UncertainCommitError } from '../src/runtime.js';
import { begin, codeFor, connectionString, deferred, eventually, fixture, prepareAgent, quote, skipPostgres, tokenFor } from './helpers.js';

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
