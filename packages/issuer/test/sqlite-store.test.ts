import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { SQLiteStore } from '../src/sqlite-store.js';
import type { Owner } from '../src/store.js';
import { prepareAgent, beginSignIn, finishSignIn } from './sqlite-fixtures.js';

const owner = (id: string): Owner => ({ id, ownerSub: `sub-${id}`, email: `${id}@example.com`, emailVerified: true, verifiedVia: 'passkey', createdAt: 1 });
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'agentlogin-sqlite-'));
  return { path: join(directory, 'issuer.db'), cleanup: () => rm(directory, { recursive: true, force: true }) };
}

test('SQLite connections share committed state and retain reservations across reopen', async () => {
  const f = await fixture();
  const a = new SQLiteStore(f.path);
  const b = new SQLiteStore(f.path);
  try {
    await a.putOwner(owner('first'));
    assert.deepEqual(await b.getOwner('first'), owner('first'));
    await b.putOwner(owner('second'));
    assert.deepEqual(await a.getOwner('second'), owner('second'));
    await prepareAgent(a, 'one');
    await prepareAgent(b, 'two');
    const held = await beginSignIn(a, 'one', 'one', 'client', 1);
    assert.equal(held.status, 'ready');
    a.close();
    b.close();
    const reopened = new SQLiteStore(f.path);
    try {
      assert.deepEqual(await reopened.getOwner('first'), owner('first'));
      assert.deepEqual(await reopened.getOwner('second'), owner('second'));
      assert.equal((await beginSignIn(reopened, 'two', 'two', 'client', 1)).reason, 'signup_limit_reached', 'nested reservation maps persist');
      await reopened.updateTransaction({ ...held, status: 'denied', reason: 'cancelled' }, held.version, { now: 1 });
      const next = await beginSignIn(reopened, 'two', 'two-again', 'client', 1);
      assert.equal(next.status, 'ready');
      assert.equal((await finishSignIn(reopened, next))?.status, 'completed');
      assert.equal(await reopened.signupsEver('owner', 'client'), 1);
      assert.equal((await reopened.getCode('code-two-again'))?.used, false);
    } finally { reopened.close(); }
    await assert.rejects(a.getOwner('first'), /closed/);
  } finally { a.close(); b.close(); await f.cleanup(); }
});

test('a failed SQLite write rolls back the complete operation and releases the lock', async () => {
  const f = await fixture();
  const store = new SQLiteStore(f.path);
  const inspection = new DatabaseSync(f.path);
  try {
    await store.putOwner(owner('kept'));
    await prepareAgent(store, 'rollback');
    const ready = await beginSignIn(store, 'rollback', 'rollback-tx', 'rollback-client', 1);
    assert.equal(ready.status, 'ready');
    inspection.exec("CREATE TRIGGER refuse_write BEFORE UPDATE ON agentlogin_state BEGIN SELECT RAISE(ABORT, 'injected write failure'); END");
    await assert.rejects(store.putOwner(owner('rolled-back')), /injected write failure/);
    await assert.rejects(finishSignIn(store, ready), /injected write failure/);
    inspection.exec('DROP TRIGGER refuse_write');
    assert.equal(await store.getOwner('rolled-back'), undefined);
    assert.deepEqual(await store.getOwner('kept'), owner('kept'));
    assert.equal((await store.getTransaction(ready.id))?.status, 'ready');
    assert.equal(await store.getCode(`code-${ready.id}`), undefined);
    assert.equal(await store.getAccount('rollback@example.com', 'rollback-client'), undefined);
    assert.equal(await store.signupsEver('owner', 'rollback-client'), 0);
    assert.equal((await finishSignIn(store, ready))?.status, 'completed', 'the original reservation survives rollback');
    assert.equal(await store.signupsEver('owner', 'rollback-client'), 1);
    await store.putOwner(owner('after-failure'));
    assert.deepEqual(await store.getOwner('after-failure'), owner('after-failure'));
  } finally { inspection.close(); store.close(); await f.cleanup(); }
});

test('independent SQLite writer processes lose no successful writes and cannot exceed a signup cap', { timeout: 30_000 }, async () => {
  const f = await fixture();
  const store = new SQLiteStore(f.path);
  const children: ReturnType<typeof spawn>[] = [];
  const code = `
    import { SQLiteStore } from ${JSON.stringify(new URL('../src/sqlite-store.ts', import.meta.url).href)};
    import { prepareAgent, beginSignIn, finishSignIn } from ${JSON.stringify(new URL('./sqlite-fixtures.ts', import.meta.url).href)};
    const store = new SQLiteStore(process.argv[1]);
    const id = process.argv[2];
    await prepareAgent(store, id);
    process.send('ready');
    process.once('message', async () => {
      try {
        const reservation = await beginSignIn(store, id, id + '-capped', 'capped', 1);
        const admitted = reservation.status === 'ready';
        if (admitted) await finishSignIn(store, reservation);
        for (let n = 0; n < 40; n += 1) {
          const ready = await beginSignIn(store, id, id + '-' + n, 'uncapped');
          if ((await finishSignIn(store, ready))?.status !== 'completed') throw new Error('sign-in failed');
        }
        store.close();
        process.send({ admitted });
        process.disconnect();
      } catch (error) { console.error(error); process.exit(1); }
    });
  `;
  try {
    const workers = Array.from({ length: 4 }, (_, id) => {
      const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', code, f.path, String(id)], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
      children.push(child);
      let stderr = '';
      let admitted = false;
      child.stderr!.on('data', (chunk) => { stderr += chunk; });
      const ready = new Promise<void>((resolve, reject) => {
        child.once('error', reject);
        child.on('message', (message) => { if (message === 'ready') resolve(); });
        child.once('exit', (status) => { if (status !== 0) reject(new Error(`worker ${id}: ${status}: ${stderr}`)); });
      });
      child.on('message', (message) => { if (message && typeof message === 'object' && 'admitted' in message) admitted = message.admitted === true; });
      const finished = new Promise<boolean>((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (status) => status === 0 ? resolve(admitted) : reject(new Error(`worker ${id}: ${status}: ${stderr}`)));
      });
      void finished.catch(() => undefined); // ready may reject first; retain the failure for the later joined wait.
      return { child, ready, finished };
    });
    await Promise.all(workers.map((worker) => worker.ready));
    for (const worker of workers) worker.child.send('go');
    assert.equal((await Promise.all(workers.map((worker) => worker.finished))).filter(Boolean).length, 1);
    assert.equal(await store.signupsEver('owner', 'capped'), 1);
    assert.equal(await store.signupsEver('owner', 'uncapped'), 4);
    for (let id = 0; id < 4; id += 1) {
      assert.equal((await store.getAccount(`${id}@example.com`, 'uncapped'))?.signInCount, 40);
      for (let n = 0; n < 40; n += 1) assert.equal((await store.getCode(`code-${id}-${n}`))?.used, false);
    }
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill();
    store.close();
    await f.cleanup();
  }
});
