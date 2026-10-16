import assert from 'node:assert/strict';
import { test } from 'node:test';
import { begin, codeFor, deferred, fixture, prepareAgent, skipPostgres } from './helpers.js';

const options = { skip: skipPostgres, timeout: 30_000 };

test('PostgreSQL management resolution retains its snapshot identity across deletion and same-owner recreation', options, async (t) => {
  let armed = false;
  const resolved = deferred(), release = deferred();
  const f = await fixture(t, { async onCheckpoint(event) {
    if (armed && event.phase === 'management_resolved') {
      armed = false;
      resolved.resolve();
      await release.promise;
    }
  } });
  const subject = await prepareAgent(f.store, f.now(), 'management');
  const credential = { hash: 'delegated-management', ownerId: subject.agent.ownerId, kind: 'delegated' as const, handle: subject.agent.handle, createdAt: f.now() };
  await f.store.putCredential(credential);
  armed = true;
  const resolving = f.store.resolveManagement(credential.hash, subject.agent.handle);
  await resolved.promise;
  try {
    assert.equal(await f.peer.deleteAgent(subject.agent.handle, subject.agent.sub, f.now()), true);
    assert.equal(await f.peer.putAgent({ ...subject.agent, sub: 'replacement-sub' }), true);
  } finally { release.resolve(); }
  const authorization = await resolving;
  assert.deepEqual(authorization, { ...credential, agentSub: subject.agent.sub });
  assert.equal(await f.peer.resolveManagement(credential.hash, subject.agent.handle), 'invalid_token');
  assert.equal(typeof authorization, 'object');
  if (typeof authorization !== 'object') assert.fail('expected the original snapshot authorization');
  assert.equal(await f.peer.readManagementKeys(subject.agent.handle, authorization), undefined);
  assert.equal(await f.peer.readManagementAccounts(subject.agent.handle, authorization), undefined);
});

for (const resource of ['keys', 'accounts'] as const) {
  test(`PostgreSQL protected ${resource} read preserves one snapshot during Agent replacement`, options, async (t) => {
    let armed = false;
    const read = deferred(), release = deferred();
    const f = await fixture(t, { async onCheckpoint(event) {
      if (armed && event.phase === `management_${resource}_read`) {
        armed = false;
        read.resolve();
        await release.promise;
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'management');
    const transaction = await begin(f.store, f.now(), 'management', 'management-account');
    await f.store.completeTransaction(transaction, transaction.version, codeFor(transaction, f.now()), f.now());
    const expected = resource === 'keys' ? await f.store.listKeys(subject.agent.handle) : await f.store.listAccounts(subject.agent.handle);
    armed = true;
    const reading = resource === 'keys'
      ? f.store.readManagementKeys(subject.agent.handle, subject.authorization, subject.key.kid)
      : f.store.readManagementAccounts(subject.agent.handle, subject.authorization);
    await read.promise;
    try {
      assert.equal(await f.peer.deleteAgent(subject.agent.handle, subject.agent.sub, f.now()), true);
      assert.equal(await f.peer.putAgent({ ...subject.agent, sub: 'replacement-sub' }), true);
      const replacement = { ...subject.key, kid: 'replacement-key', enrollment: 'replacement-enrollment', agentSub: 'replacement-sub' };
      assert.equal(await f.peer.insertKey(replacement, f.now(), { ...subject.authorization, agentSub: 'replacement-sub' }), 'ok');
    } finally { release.resolve(); }
    assert.deepEqual(await reading, expected, 'a read may return its earlier snapshot, but cannot expose the replacement identity');
    assert.equal(await f.peer.readManagementKeys(subject.agent.handle, subject.authorization), undefined);
    assert.equal(await f.peer.readManagementAccounts(subject.agent.handle, subject.authorization), undefined);
    const fresh = await f.peer.resolveManagement(subject.authorization.hash, subject.agent.handle);
    if (typeof fresh !== 'object') assert.fail('owner credential must resolve to the replacement Agent');
    assert.equal(fresh.agentSub, 'replacement-sub');
    assert.deepEqual(await f.peer.readManagementAccounts(subject.agent.handle, fresh), []);
    assert.deepEqual(await f.peer.readManagementKeys(subject.agent.handle, fresh, subject.key.kid), []);
    assert.equal((await f.peer.readManagementKeys(subject.agent.handle, fresh))?.[0]?.kid, 'replacement-key');
  });
}

for (const operation of ['patchKey', 'revokeKey'] as const) {
  test(`PostgreSQL authorized ${operation} retries after deletion without mutating a recreated Agent`, options, async (t) => {
    let armed = false;
    const checked = deferred(), release = deferred();
    const attempts: number[] = [];
    const f = await fixture(t, { async onCheckpoint(event) {
      if (!armed || event.operation !== operation) return;
      if (event.phase === 'afterBegin') attempts.push(event.attempt);
      if (event.phase === 'before_agent_lock' && event.attempt === 0) {
        checked.resolve();
        await release.promise;
      }
    } });
    const subject = await prepareAgent(f.store, f.now(), 'management');
    armed = true;
    const mutating = operation === 'patchKey'
      ? f.store.patchKey(subject.key.kid, subject.key.enrollment, { name: 'stale mutation' }, subject.authorization)
      : f.store.revokeKey(subject.key.kid, subject.key.enrollment, f.now(), subject.authorization);
    await checked.promise;
    try {
      assert.equal(await f.peer.deleteAgent(subject.agent.handle, subject.agent.sub, f.now()), true);
      assert.equal(await f.peer.putAgent({ ...subject.agent, sub: 'replacement-sub' }), true);
      const replacement = { ...subject.key, kid: 'replacement-key', enrollment: 'replacement-enrollment', agentSub: 'replacement-sub' };
      assert.equal(await f.peer.insertKey(replacement, f.now(), { ...subject.authorization, agentSub: 'replacement-sub' }), 'ok');
    } finally { release.resolve(); }
    assert.equal(await mutating, undefined);
    assert.ok(attempts.length >= 2, 'the stale SERIALIZABLE snapshot must roll back and re-run its checks');
    const replacement = await f.peer.getKey('replacement-key', subject.agent.handle);
    assert.equal(replacement?.status, 'pending');
    assert.equal(replacement?.name, undefined);
  });

  for (const change of ['revoked', 'downgraded'] as const) {
    test(`PostgreSQL authorized ${operation} rechecks a ${change} credential on a real serialization retry`, options, async (t) => {
      let armed = false;
      const checked = deferred(), release = deferred();
      const attempts: number[] = [];
      const f = await fixture(t, { async onCheckpoint(event) {
        if (!armed || event.operation !== operation) return;
        if (event.phase === 'afterBegin') attempts.push(event.attempt);
        if (event.phase === 'management_key_authorized' && event.attempt === 0) {
          checked.resolve();
          await release.promise;
        }
      } });
      const subject = await prepareAgent(f.store, f.now(), 'management');
      armed = true;
      const mutating = operation === 'patchKey'
        ? f.store.patchKey(subject.key.kid, subject.key.enrollment, { shareOwner: true }, subject.authorization)
        : f.store.revokeKey(subject.key.kid, subject.key.enrollment, f.now(), subject.authorization);
      await checked.promise;
      try {
        if (change === 'revoked') await f.peer.deleteCredential(subject.authorization.hash);
        else {
          const credential = await f.peer.getCredential(subject.authorization.hash);
          assert.ok(credential);
          await f.peer.putCredential({ ...credential, sessionAuth: 'email_only' });
        }
        // Changing the already-read key forces a genuine 40001 on the stale mutation's write.
        await f.peer.patchKey(subject.key.kid, subject.key.enrollment, { name: 'current name' });
      } finally { release.resolve(); }
      assert.equal(await mutating, undefined);
      assert.ok(attempts.length >= 2, 'the mutation must re-run after a serialization failure');
      const key = await f.peer.getKey(subject.key.kid, subject.agent.handle);
      assert.equal(key?.name, 'current name');
      assert.equal(key?.permissions.share_owner, false);
      assert.equal(key?.status, 'active');
    });
  }
}
