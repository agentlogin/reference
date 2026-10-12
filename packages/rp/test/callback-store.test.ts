import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  MemoryCallbackStateStore, SqliteCallbackStateStore, RelyingParty, createHandlers,
  type CallbackStateStore, type SignIn,
} from '../src/index.js';

const execFileAsync = promisify(execFile);

test('callback stores retain consumed state, reject replacement and fail closed after expiry or loss', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agentlogin-rp-store-'));
  let now = 10_000;
  const sqlite = new SqliteCallbackStateStore(join(directory, 'callbacks.sqlite'), { now: () => now });
  try {
    for (const store of [new MemoryCallbackStateStore({ now: () => now }), sqlite]) {
      assert.equal(await store.claim('absent'), 'missing');
      assert.equal(await store.register('pending', now + 100), true);
      assert.equal(await store.register('pending', now + 200), false);
      assert.deepEqual(await Promise.all([store.claim('pending'), store.claim('pending')]), ['claimed', 'duplicate']);
      assert.equal(await store.register('pending', now + 300), false, 'registration cannot reset a claim');
      now += 100;
      assert.equal(await store.claim('pending'), 'missing', 'original expiry was not extended');
    }
    assert.equal(await new MemoryCallbackStateStore().claim('pending'), 'missing', 'lost state does not recreate a claim');
  } finally { sqlite.close(); await rm(directory, { recursive: true, force: true }); }
});

test('memory capacity does not evict a still-valid consumed state', async () => {
  let now = 10_000;
  const store = new MemoryCallbackStateStore({ now: () => now, maxEntries: 1 });
  assert.equal(await store.register('first', now + 100), true);
  assert.equal(await store.claim('first'), 'claimed');
  await assert.rejects(store.register('second', now + 100), /full/);
  assert.equal(await store.claim('first'), 'duplicate');
  now += 100;
  assert.equal(await store.register('second', now + 100), true);
});

test('SQLite callback claims are atomic across independent Node processes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agentlogin-rp-processes-'));
  const filename = join(directory, 'callbacks.sqlite');
  const store = new SqliteCallbackStateStore(filename);
  try {
    await store.register('process-race', Date.now() + 60_000);
    const moduleUrl = new URL('../src/callback-store.ts', import.meta.url).href;
    const script = `import { SqliteCallbackStateStore } from ${JSON.stringify(moduleUrl)};
      const store = new SqliteCallbackStateStore(process.argv[1]);
      process.stdout.write(await store.claim('process-race'));
      store.close();`;
    const attempts = await Promise.all(Array.from({ length: 6 }, () => execFileAsync(process.execPath,
      ['--import', 'tsx', '--input-type=module', '-e', script, filename])));
    assert.equal(attempts.filter((r) => r.stdout === 'claimed').length, 1);
    assert.equal(attempts.filter((r) => r.stdout === 'duplicate').length, 5);
    assert.equal(await store.claim('process-race'), 'duplicate');
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

class TestRelyingParty extends RelyingParty {
  completions = 0;
  override async begin() {
    const state = randomBytes(16).toString('hex');
    return { url: `https://issuer.example/authorize?state=${state}`, pending: { state, issuer: 'https://issuer.example', nonce: 'nonce', verifier: 'verifier' } };
  }
  override async complete(): Promise<SignIn> {
    this.completions += 1;
    return { agent: { iss: 'https://issuer.example', sub: 'sub', key: 'https://issuer.example sub', scopes: ['openid'] }, claims: {}, issuer: 'https://issuer.example', accessToken: 'token', accessTokenExpiresAt: 0 };
  }
}

const testRp = () => new TestRelyingParty({ clientId: 'test-client', redirectUri: 'https://rp.example/callback', issuers: ['https://issuer.example'], stateSecret: 'secret'.repeat(8) });

test('store failures prevent exchanges; application failures do not release claims', async () => {
  const rp = testRp();
  const store = new MemoryCallbackStateStore();
  const appFailure = new Error('session persistence failed');
  const handlers = createHandlers(rp, { callbackStore: store, onSignIn: () => { throw appFailure; }, log: () => {} });
  const start = await handlers.login(new Request('https://rp.example/login'));
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  const request = () => new Request(`https://rp.example/callback?state=${state}&iss=https://issuer.example&code=code`, {
    headers: { cookie: start.headers.get('set-cookie')!.split(';')[0]! },
  });
  let claimFails = true;
  const unavailable: CallbackStateStore = {
    register: async () => { throw new Error('offline'); },
    claim: async (key) => { if (claimFails) throw new Error('offline'); return store.claim(key); },
  };
  const other = createHandlers(rp, { callbackStore: unavailable, onSignIn: () => new Response('ok'), log: () => {} });
  assert.equal((await other.login(new Request('https://rp.example/login'))).status, 500);
  const failed = await other.callback(request());
  assert.equal(failed.status, 500);
  assert.match(await failed.text(), /state_store_failed/);
  assert.equal(rp.completions, 0);

  await assert.rejects(handlers.callback(request()), (e) => e === appFailure);
  assert.equal(rp.completions, 1);
  claimFails = false;
  const replay = await other.callback(request());
  assert.equal(replay.status, 400);
  assert.match(await replay.text(), /duplicate_callback/);
  assert.equal(rp.completions, 1, 'onSignIn failure must not permit a second token exchange');

  const lostStore = createHandlers(rp, { callbackStore: new MemoryCallbackStateStore(), onSignIn: () => new Response('ok') });
  assert.equal((await lostStore.callback(request())).status, 400);
  assert.equal(rp.completions, 1, 'a valid cookie cannot recreate missing server state');
});
