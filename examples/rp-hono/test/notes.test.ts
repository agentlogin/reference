import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { ApplicationSessionUncertainCommitError } from '../postgres-session-store.js';
import { MemorySessionStore, NoteError } from '../session-store.js';
import { fixture, session, sid, skipPostgres } from './helpers.js';

const id = () => randomBytes(16).toString('hex');

test('notes isolate immutable accounts and preserve idempotency across sessions', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t), a = sid(), b = sid(), other = sid(), request = id();
  await f.store.create(a, session(f.now()));
  await f.peer.create(b, session(f.now()));
  await f.store.create(other, session(f.now(), 'different-subject'));
  const [one, two] = await Promise.all([f.store.saveNote(a, request, 'Private note'), f.peer.saveNote(b, request, 'Private note')]);
  assert.deepEqual(one, two);
  assert.deepEqual(await f.peer.listNotes(b), [one]);
  assert.deepEqual(await f.peer.listNotes(other), []);
  await assert.rejects(f.peer.saveNote(b, request, 'Changed note'), (e) => e instanceof NoteError && e.code === 'idempotency_conflict');
  await f.peer.revoke(a);
  await assert.rejects(f.store.saveNote(a, id(), 'after logout'), NoteError);
  assert.equal(await f.peer.listNotes(a), undefined);
  assert.equal((await f.peer.listNotes(b))?.length, 1);
});

for (const phase of ['after-lock', 'before-commit'] as const) {
  test(`note save rolls back when authority expires ${phase}`, { skip: skipPostgres }, async (t) => {
    let expire = false;
    const f = await fixture(t, { onCheckpoint: async (e) => {
      if (expire && e.operation === 'saveNote' && e.phase === phase) { expire = false; await f.advance(600); }
    } });
    const cookie = sid(); await f.store.create(cookie, session(f.now()));
    expire = true;
    await assert.rejects(f.store.saveNote(cookie, id(), 'must not persist'), (e) => e instanceof NoteError && e.code === 'reauthentication_required');
    assert.deepEqual(await f.peer.listNotes(cookie), []);
  });
}

test('uncertain note commits reconcile using the same account and request id', { skip: skipPostgres }, async (t) => {
  let fail = true;
  const f = await fixture(t, { onCheckpoint: (e) => {
    if (fail && e.operation === 'saveNote' && e.phase === 'after-commit') { fail = false; throw new Error('lost acknowledgement'); }
  } });
  const cookie = sid(), request = id(); await f.store.create(cookie, session(f.now()));
  await assert.rejects(f.store.saveNote(cookie, request, 'saved once'), ApplicationSessionUncertainCommitError);
  const result = await f.peer.saveNote(cookie, request, 'saved once');
  assert.deepEqual(await f.peer.listNotes(cookie), [result]);
});

test('logout waits for an authorized business write and prevents every subsequent write', { skip: skipPostgres }, async (t) => {
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((r) => { release = r; }), ready = new Promise<void>((r) => { entered = r; });
  const f = await fixture(t, { onCheckpoint: async (e) => {
    if (e.operation === 'saveNote' && e.phase === 'after-lock') { entered(); await gate; }
  } });
  const cookie = sid(); await f.store.create(cookie, session(f.now()));
  const write = f.store.saveNote(cookie, id(), 'before logout');
  await ready;
  const logout = f.peer.revoke(cookie);
  release(); await write; await logout;
  await assert.rejects(f.peer.saveNote(cookie, id(), 'after logout'), NoteError);
});

test('memory notes enforce matching limits, identity and expiry semantics', async () => {
  let now = 10_000; const store = new MemorySessionStore(() => now), cookie = sid(), request = id();
  await store.create(cookie, session(now));
  const note = await store.saveNote(cookie, request, '<script>untrusted text</script>');
  assert.deepEqual(await store.listNotes(cookie), [note]);
  await assert.rejects(store.saveNote(cookie, request, 'different'), NoteError);
  await assert.rejects(store.saveNote(cookie, id(), '🙂'.repeat(1025)), TypeError);
  for (const badId of [1234567890123456, ['abcdefghijklmnop'], { toString: () => 'abcdefghijklmnop' }]) {
    await assert.rejects(store.saveNote(cookie, badId as unknown as string, 'invalid identifier'), TypeError);
  }
  now += 600;
  await assert.rejects(store.saveNote(cookie, id(), 'expired'), NoteError);
  assert.deepEqual(await store.listNotes(cookie), [note], 'reading does not need to retain an expired issuer credential');
  await store.close();
});
