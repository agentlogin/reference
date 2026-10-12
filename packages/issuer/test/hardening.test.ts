// Each race is placed at a real asynchronous store boundary. SQLite uses two independent connections.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { MemoryStore, type Store } from '../src/index.js';
import { SQLiteStore } from '../src/sqlite-store.js';
import { world } from './fixtures.js';
import { hookable, snapshotting } from './stores.js';

type World = Awaited<ReturnType<typeof world>>;
type Key = Awaited<ReturnType<World['newKey']>>;

async function setup(t: TestContext, backend: 'memory' | 'sqlite') {
  let stores: [Store, Store];
  if (backend === 'sqlite') {
    const dir = mkdtempSync(join(tmpdir(), 'agentlogin-races-'));
    const first = new SQLiteStore(join(dir, 'issuer.sqlite'));
    const second = new SQLiteStore(join(dir, 'issuer.sqlite'));
    stores = [first, second];
    t.after(() => { first.close(); second.close(); rmSync(dir, { recursive: true, force: true }); });
  } else {
    const shared = snapshotting(new MemoryStore());
    stores = [shared, shared];
  }
  const hooked = hookable(stores[0]);
  const w = await world({ store: hooked.store, stores: [hooked.store, stores[1]], instances: 2 });
  return { w, after: hooked.after, secondStore: stores[1], other: w.on(1) };
}

async function proveOnSecond(w: World, handle: string, key: Key, enrollment: { json: any }) {
  const now = enrollment.json.created_at as number;
  const proof = await new SignJWT({ nonce: enrollment.json.challenge, jti: randomBytes(16).toString('base64url') })
    .setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid })
    .setIssuer(handle).setSubject(handle).setAudience('https://issuer.test')
    .setIssuedAt(now).setExpirationTime(now + 60).sign(key.privateKey);
  const response = await w.on(1)('POST', enrollment.json.proof_url, { json: { proof } });
  assert.equal(response.status, 200, response.text);
}

for (const backend of ['memory', 'sqlite'] as const) {
  test(`${backend}: enrollment cannot cross deletion and handle reassignment to another Owner`, async (t) => {
    const { w, after, secondStore, other } = await setup(t, backend);
    const handle = 'scout@example.com';
    assert.equal((await w.req('POST', '/admin/agents', { json: { handle, owner_id: w.owner.owner_id }, headers: w.admin })).status, 201);
    const original = (await secondStore.getAgent(handle))!;
    const newOwner = await other('POST', '/admin/owners', { json: { email: 'replacement@example.org', session_auth: 'passkey' }, headers: w.admin });
    assert.equal(newOwner.status, 201);
    const key = await w.newKey();
    let changed = false;
    after('getAgent', async () => {
      assert.equal((await other('DELETE', `/admin/agents/${encodeURIComponent(handle)}`, { headers: w.admin })).status, 204);
      assert.equal((await other('POST', '/admin/agents', { json: { handle, owner_id: newOwner.json.owner_id }, headers: w.admin })).status, 201);
      changed = true;
    });
    const stale = await w.enroll(handle, key);
    assert.ok(changed, 'the ownership change happened while authorization held the previous Agent snapshot');
    assert.equal(stale.en.status, 404, stale.en.text);
    assert.equal(await secondStore.getKey(key.kid), undefined, 'the stale owner inserted no key');
    const replacement = (await secondStore.getAgent(handle))!;
    assert.notEqual(replacement.sub, original.sub);
    assert.equal(replacement.ownerId, newOwner.json.owner_id);

    const fresh = await other('POST', `/agents/${encodeURIComponent(handle)}/keys`, {
      json: { jwk: key.jwk }, headers: { authorization: `Bearer ${newOwner.json.credential}` },
    });
    assert.equal(fresh.status, 201, fresh.text);
    await proveOnSecond(w, handle, key, fresh);
    assert.equal((await secondStore.getKey(key.kid))?.agentSub, replacement.sub);
    const client = await w.client();
    const code = await w.codeFor(client, { handle, ...key });
    assert.equal((await w.token(client, code.code, code.verifier, 1)).status, 200, 'replacement Owner can enroll and sign in normally');
  });

  test(`${backend}: losing duplicate assertion cannot release the winner's signup reservation`, async (t) => {
    const { w, after, secondStore } = await setup(t, backend);
    const first = await w.agent('scout@example.com');
    const second = await w.agent('rover@example.com');
    const client = await w.client({ max_signups_per_owner: 1 });
    const start = await w.start(client);
    let winner: Awaited<ReturnType<World['assertOn']>> | undefined;
    after('getConsent', async () => {
      winner = await w.assertOn(start.tx, first, 1);
      assert.equal(winner.status, 200, winner.text);
      assert.equal(winner.json.status, 'ready');
    });
    const loser = await w.assertOn(start.tx, first, 0);
    assert.equal(loser.status, 409, loser.text);
    assert.equal(loser.json.error, 'assertion_replayed');
    assert.ok(winner, 'second instance committed while the first assertion was suspended');

    // Try the second Agent before the winner completes, precisely when its reservation is its only cap protection.
    const secondStart = await w.start(client);
    const denied = await w.assertOn(secondStart.tx, second, 1);
    assert.equal(denied.status, 200, denied.text);
    assert.equal(denied.json.status, 'denied');
    assert.equal(denied.json.reason, 'signup_limit_reached');
    const completed = await w.cont(winner.json, 1);
    assert.equal(completed.status, 200, completed.text);
    const code = new URL(completed.json.redirect).searchParams.get('code');
    assert.ok(code);
    assert.equal((await w.token(client, code, start.verifier)).status, 200);
    assert.equal(await secondStore.signupsEver(w.owner.owner_id, client.client_id), 1);
    assert.equal((await secondStore.listAccounts(first.handle)).length, 1);
    assert.equal((await secondStore.listAccounts(second.handle)).length, 0);
  });

  test(`${backend}: stale key DELETE cannot revoke another Owner's newer enrollment of the same kid`, async (t) => {
    const { w, after, secondStore, other } = await setup(t, backend);
    const oldAgent = await w.agent('scout@example.com', 50);
    const oldEnrollment = (await secondStore.getKey(oldAgent.kid))!.enrollment;
    const handle = 'replacement@example.com';
    const newOwner = await other('POST', '/admin/owners', { json: { email: 'other-owner@example.org', session_auth: 'passkey' }, headers: w.admin });
    assert.equal(newOwner.status, 201);
    assert.equal((await other('POST', '/admin/agents', { json: { handle, owner_id: newOwner.json.owner_id }, headers: w.admin })).status, 201);
    let newEnrollment = '';
    after('getKey', async () => {
      w.advance(51);
      const fresh = await other('POST', `/agents/${encodeURIComponent(handle)}/keys`, {
        json: { jwk: oldAgent.jwk }, headers: { authorization: `Bearer ${newOwner.json.credential}` },
      });
      assert.equal(fresh.status, 201, fresh.text);
      await proveOnSecond(w, handle, oldAgent, fresh);
      newEnrollment = (await secondStore.getKey(oldAgent.kid))!.enrollment;
      assert.notEqual(newEnrollment, oldEnrollment);
    });
    assert.equal((await w.revoke(oldAgent)).status, 204);
    const current = (await secondStore.getKey(oldAgent.kid))!;
    assert.equal(current.enrollment, newEnrollment);
    assert.equal(current.handle, handle);
    assert.equal(current.status, 'active', 'stale request only names the previous enrollment');
    const client = await w.client();
    const code = await w.codeFor(client, { ...oldAgent, handle });
    assert.equal((await w.token(client, code.code, code.verifier, 1)).status, 200, 'new enrollment still signs in');
  });

  for (const target of ['agent', 'account'] as const) {
    test(`${backend}: ${target} disable and re-enable fences an assertion whose subject snapshot is already loaded`, async (t) => {
      const { w, after, secondStore, other } = await setup(t, backend);
      const agent = await w.agent('scout@example.com');
      const client = await w.client();
      if (target === 'account') {
        const initial = await w.codeFor(client, agent);
        assert.equal((await w.token(client, initial.code, initial.verifier, 1)).status, 200);
      }
      const before = await secondStore.getAccount(agent.handle, client.client_id);
      assert.equal(before?.signInCount, target === 'account' ? 1 : undefined);
      const pending = await w.start(client);
      let changed = false;
      after(target === 'agent' ? 'getAgent' : 'getAccount', async () => {
        // The assertion holds the old Agent/Account snapshot, but has not bound its identity into the transaction.
        // Invalidation scans cannot find this awaiting_agent transaction by handle; the epoch must reject its CAS.
        const snapshot = (await secondStore.getTransaction(pending.tx.transaction_id))!;
        assert.equal(snapshot.status, 'awaiting_agent');
        assert.equal(snapshot.handle, undefined);
        if (target === 'agent') {
          const path = `/admin/agents/${encodeURIComponent(agent.handle)}`;
          for (const enabled of [false, true]) {
            assert.equal((await other('PATCH', path, { json: { enabled }, headers: w.admin })).status, 200);
          }
        } else {
          const path = `/agents/${encodeURIComponent(agent.handle)}/accounts/${encodeURIComponent(client.client_id)}`;
          for (const status of ['disabled', 'enabled']) {
            assert.equal((await other('PATCH', path, { json: { status }, headers: w.cred })).status, 200);
          }
        }
        const unswept = (await secondStore.getTransaction(pending.tx.transaction_id))!;
        assert.equal(unswept.status, 'awaiting_agent', 'disable sweep could not discover this unbound assertion');
        assert.equal(unswept.version, snapshot.version, 'the transaction is unchanged by both status mutations');
        changed = true;
      });
      const rejected = await w.assertOn(pending.tx, agent);
      assert.ok(changed, 'the competing instance changed status between subject read and assertion commit');
      assert.equal(rejected.status, 200, rejected.text);
      assert.equal(rejected.json.status, 'denied');
      assert.equal(rejected.json.reason, 'access_denied');
      const afterRejection = await secondStore.getAccount(agent.handle, client.client_id);
      assert.equal(afterRejection?.signInCount, before?.signInCount, 'the stale assertion creates no Account or sign-in');
      assert.equal(await secondStore.signupsEver(w.owner.owner_id, client.client_id), target === 'account' ? 1 : 0);
      const persisted = (await secondStore.getTransaction(pending.tx.transaction_id))!;
      assert.equal(persisted.status, 'denied');
      assert.equal(persisted.codeIssued, false);

      const fresh = await w.codeFor(client, agent);
      assert.equal((await w.token(client, fresh.code, fresh.verifier, 1)).status, 200, 'fresh assertion uses the new authorization version');
      assert.equal(await secondStore.signupsEver(w.owner.owner_id, client.client_id), 1);
      assert.equal((await secondStore.getAccount(agent.handle, client.client_id))?.signInCount, target === 'account' ? 2 : 1);
    });
  }

  for (const target of ['agent', 'account'] as const) {
    test(`${backend}: ${target} disable and re-enable after completion permanently invalidates the issued code`, async (t) => {
      const { w, after, secondStore, other } = await setup(t, backend);
      const agent = await w.agent('scout@example.com');
      const client = await w.client();
      const ready = await w.ready(client, agent);
      let changed = false;
      after('completeTransaction', async () => {
        const completed = (await secondStore.getTransaction(ready.tx.transaction_id))!;
        assert.equal(completed.status, 'completed', 'hook runs after the durable completion write');
        if (target === 'agent') {
          for (const enabled of [false, true]) {
            assert.equal((await other('PATCH', `/admin/agents/${encodeURIComponent(agent.handle)}`, { json: { enabled }, headers: w.admin })).status, 200);
          }
        } else {
          const path = `/agents/${encodeURIComponent(agent.handle)}/accounts/${encodeURIComponent(client.client_id)}`;
          for (const status of ['disabled', 'enabled']) {
            assert.equal((await other('PATCH', path, { json: { status }, headers: w.cred })).status, 200);
          }
        }
        changed = true;
      });
      const completed = await w.cont(ready.tx);
      assert.ok(changed, 'disable and re-enable finished before the code was returned to the caller');
      assert.equal(completed.status, 200, completed.text);
      const oldCode = new URL(completed.json.redirect).searchParams.get('code');
      assert.ok(oldCode);
      const rejected = await w.token(client, oldCode, ready.verifier, 1);
      assert.equal(rejected.status, 400, rejected.text);
      assert.equal(rejected.json.error, 'invalid_grant');
      // Re-enabling allows a fresh authorization, without resurrecting the previous one.
      const fresh = await w.codeFor(client, agent);
      assert.equal((await w.token(client, fresh.code, fresh.verifier, 1)).status, 200);
      assert.equal(await secondStore.signupsEver(w.owner.owner_id, client.client_id), 1);
    });
  }
}
