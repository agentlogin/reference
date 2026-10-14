import assert from 'node:assert/strict';
import type { CallbackStateStore } from '../src/callback-store.js';

/** Observable contract shared by every bundled callback backend. Clocks use Unix milliseconds. */
export async function callbackContract(store: CallbackStateStore, now: () => number, advance: (ms: number) => void | Promise<void>) {
  assert.equal(await store.claim('absent'), 'missing');
  const expiry = now() + 100;
  assert.equal(await store.register('pending', expiry), true);
  assert.equal(await store.register('pending', expiry + 100), false);
  const claims = await Promise.all(Array.from({ length: 8 }, () => store.claim('pending')));
  assert.equal(claims.filter((value) => value === 'claimed').length, 1);
  assert.equal(claims.filter((value) => value === 'duplicate').length, 7);
  assert.equal(await store.register('pending', expiry + 200), false, 'registration cannot reset consumption or expiry');
  assert.equal(await store.register('unused', expiry), true);
  await advance(100);
  assert.equal(await store.claim('pending'), 'missing', 'used state expires at its original deadline');
  assert.equal(await store.claim('unused'), 'missing', 'unused state also expires at equality');
  assert.equal(await store.claim('absent'), 'missing', 'claim does not register missing state');
}
