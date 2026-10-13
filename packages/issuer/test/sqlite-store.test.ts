import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { SQLiteStore } from '../src/sqlite-store.js';
import type { AgentKey, Owner } from '../src/store.js';
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

test('SQLite reads and effective polling neither write nor wait for an existing WAL writer', async () => {
  const f = await fixture();
  const store = new SQLiteStore(f.path, { busyTimeoutMs: 0 });
  const writer = new DatabaseSync(f.path);
  try {
    await prepareAgent(store, 'reader');
    const ready = await beginSignIn(store, 'reader', 'read-tx', 'read-client', 1);
    // The trigger catches an accidental unchanged-snapshot UPDATE; the held writer catches BEGIN IMMEDIATE.
    writer.exec("CREATE TRIGGER refuse_read_write BEFORE UPDATE ON agentlogin_state BEGIN SELECT RAISE(ABORT, 'read attempted write'); END");
    writer.exec('BEGIN IMMEDIATE');
    assert.equal((await store.getTransaction(ready.id))?.status, 'ready');
    const effective = await store.readTransaction(ready.id, { now: ready.expiresAt + 1, retainFor: 30 });
    assert.equal(effective?.status, 'expired');
    assert.equal((await store.getTransaction(ready.id))?.status, 'ready');
    writer.exec('ROLLBACK');
    writer.exec('DROP TRIGGER refuse_read_write');
  } finally {
    try { writer.exec('ROLLBACK'); } catch { /* no active transaction */ }
    writer.close(); store.close(); await f.cleanup();
  }
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

test('SQLite loads legacy key indexes, preserves history, and persists scoped keys in a version 2 snapshot', async () => {
  const f = await fixture();
  let store = new SQLiteStore(f.path);
  const database = new DatabaseSync(f.path);
  try {
    await prepareAgent(store, 'first');
    await prepareAgent(store, 'second');
    const completed = await beginSignIn(store, 'first', 'completed', 'client');
    await finishSignIn(store, completed);
    const held = await beginSignIn(store, 'first', 'held', 'capped-client', 1);
    await store.revokeKey('key-second', 'enrollment-second', 2);
    store.close();
    const snapshot = JSON.parse(database.prepare('SELECT snapshot FROM agentlogin_state WHERE id = 1').get()!.snapshot as string);
    snapshot.version = 1;
    snapshot.maps.keys = snapshot.maps.keys.map(([, key]: [string, AgentKey]) => [key.kid, key]);
    const legacy = JSON.stringify(snapshot);
    database.prepare('UPDATE agentlogin_state SET snapshot = ? WHERE id = 1').run(legacy);
    store = new SQLiteStore(f.path);
    assert.equal((await store.getKey('key-first', 'first@example.com'))?.enrollment, 'enrollment-first');
    assert.equal(await store.wasRevoked('second@example.com', 'key-second'), true);
    assert.equal((await store.getCode('code-completed'))?.used, false);
    assert.equal(await store.signupsEver('owner', 'client'), 1);
    assert.equal((await store.getTransaction(held.id))?.passedCap, true);
    assert.equal(database.prepare('SELECT snapshot FROM agentlogin_state WHERE id = 1').get()!.snapshot, legacy, 'migration on a read stays read-only');
    const first = (await store.getKey('key-first', 'first@example.com'))!;
    const pending: AgentKey = { ...first, handle: 'second@example.com', agentSub: 'second', enrollment: 'second-pending',
      status: 'pending', challenge: { value: 'second-challenge', expiresAt: 100 } };
    const credential = (await store.getCredential('credential-second'))!;
    assert.equal(await store.insertKey(pending, 3, { ...credential, agentSub: 'second' }), 'ok');
    const migrated = JSON.parse(database.prepare('SELECT snapshot FROM agentlogin_state WHERE id = 1').get()!.snapshot as string);
    assert.equal(migrated.version, 2, 'older binaries must reject the new key representation');
    const { keys: _oldKeys, ...oldMaps } = snapshot.maps;
    const { keys: _newKeys, ...newMaps } = migrated.maps;
    assert.deepEqual(newMaps, oldMaps);
    assert.deepEqual(migrated.revoked, snapshot.revoked);
    assert.deepEqual(migrated.reservations, snapshot.reservations);
    store.close();
    store = new SQLiteStore(f.path);
    assert.equal((await store.getKey('key-first', 'first@example.com'))?.status, 'active');
    assert.equal((await store.getKey('key-first', 'second@example.com'))?.status, 'pending');
    assert.equal((await store.listKeys('second@example.com')).length, 2);
    assert.equal((await store.getTransaction(held.id))?.passedCap, true);
  } finally { database.close(); store.close(); await f.cleanup(); }
});
