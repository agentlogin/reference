// Revocation and expiry are checked where transaction authority takes effect, across independent connections.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeJwt } from 'jose';
import { DEFAULT_CONSTANTS, MemoryStore, SQLiteStore, type Store } from '../src/index.js';
import { world } from './fixtures.js';
import { hookable, snapshotting } from './stores.js';

async function setup(t: TestContext, backend: 'memory' | 'sqlite') {
  let stores: [Store, Store];
  if (backend === 'sqlite') {
    const dir = mkdtempSync(join(tmpdir(), 'agentlogin-authority-'));
    const first = new SQLiteStore(join(dir, 'issuer.sqlite'));
    const second = new SQLiteStore(join(dir, 'issuer.sqlite'));
    stores = [first, second];
    t.after(() => { first.close(); second.close(); rmSync(dir, { recursive: true, force: true }); });
  } else {
    const shared = snapshotting(new MemoryStore());
    stores = [shared, shared];
  }
  const hooks = hookable(stores[0]);
  const before = new Map<keyof Store, () => Promise<void>>();
  const store = new Proxy(hooks.store, {
    get(target, name, receiver) {
      const value = Reflect.get(target, name, receiver);
      if (typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        const hook = before.get(name as keyof Store);
        if (hook) { before.delete(name as keyof Store); await hook(); }
        return value.apply(target, args);
      };
    },
  });
  const w = await world({ store, stores: [store, stores[1]], instances: 2 });
  return { w, after: hooks.after, before: (method: keyof Store, hook: () => Promise<void>) => before.set(method, hook) };
}

for (const backend of ['memory', 'sqlite'] as const) {
  for (const outcome of ['ready', 'awaiting_consent', 'awaiting_owner', 'completed', 'denied', 'expired'] as const) {
    test(`${backend}: explicit revocation rejects retained ${outcome} transaction bearers but preserves anonymous reads and session authority`, async (t) => {
      const { w } = await setup(t, backend);
      const agent = await w.agent('scout@example.com');
      const client = await w.client();
      const started = await w.start(client, outcome === 'awaiting_owner' ? { scope: 'openid owner_profile' } : {});
      const accepted = await w.assertOn(started.tx, agent, 0, { accept_disclosure: outcome !== 'awaiting_consent' && outcome !== 'denied', deliver_to_session: true });
      assert.equal(accepted.status, 200, accepted.text);
      if (outcome === 'completed') assert.equal((await w.cont(accepted.json)).status, 200);
      if (outcome === 'denied') assert.equal((await w.req('POST', `${started.tx.url}/review`, {
        json: { decision: 'deny' }, headers: { authorization: `Bearer ${accepted.json.transaction_token}` },
      })).status, 200);
      if (outcome === 'expired') w.advance(DEFAULT_CONSTANTS.T_TXN);
      const previous = (await w.store.readTransaction(started.tx.transaction_id, { now: outcome === 'expired' ? started.tx.expires_at : started.tx.expires_at - DEFAULT_CONSTANTS.T_TXN, retainFor: DEFAULT_CONSTANTS.T_RETAIN }))!;
      const continueUrl = `${started.tx.url}/continue/${previous.continueSecret}`;
      assert.equal((await w.revoke(agent)).status, 204);
      const headers = { authorization: `Bearer ${accepted.json.transaction_token}` };
      for (const [method, path, json] of [
        ['GET', started.tx.url, undefined],
        ['POST', `${started.tx.url}/review`, { decision: 'invalid' }],
        ['GET', continueUrl, undefined],
      ] as const) {
        const rejected = await w.req(method, path, { headers, json });
        assert.equal(rejected.status, 401, rejected.text);
        assert.equal(rejected.json.error, 'invalid_token');
        assert.equal(rejected.json.next.url, undefined, 'a revoked bearer cannot recover the continue URL from an error');
      }
      const anonymous = await w.req('GET', started.tx.url);
      assert.equal(anonymous.status, 200, anonymous.text);
      assert.equal(anonymous.json.next.url, undefined);
      const sessionHeaders = { authorization: `Bearer ${started.tx.session_token}` };
      const session = await w.req('GET', started.tx.url, { headers: sessionHeaders });
      assert.equal(session.status, 200, session.text);
      const continued = await w.req('GET', continueUrl, { headers: sessionHeaders });
      assert.equal(continued.status, outcome === 'completed' ? 410 : 200, continued.text);
      if (outcome !== 'completed') assert.equal(new URL(continued.json.redirect).searchParams.get('code'), null);
      const stored = (await w.store.getTransaction(started.tx.transaction_id))!;
      assert.equal(stored.transactionTokenHash, undefined);
      if (['completed', 'denied', 'expired'].includes(outcome)) {
        assert.equal(stored.status, previous.status);
        assert.equal(stored.terminalAt, previous.terminalAt);
      }
    });
  }

  for (const action of ['read', 'review', 'continue', 'terminal continue'] as const) {
    test(`${backend}: ${action} cannot use a viewer identified before explicit revocation`, async (t) => {
      const { w, after, before } = await setup(t, backend);
      const agent = await w.agent('race@example.com');
      const client = await w.client();
      const started = await w.start(client);
      const accepted = await w.assertOn(started.tx, agent, 0, { accept_disclosure: action !== 'review' });
      assert.equal(accepted.status, 200, accepted.text);
      const stored = (await w.store.getTransaction(started.tx.transaction_id))!;
      const continueUrl = `${started.tx.url}/continue/${stored.continueSecret}`;
      if (action === 'terminal continue') w.advance(DEFAULT_CONSTANTS.T_TXN);
      const revoke = async () => {
        const result = await w.on(1)('DELETE', `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`, { headers: w.cred });
        assert.equal(result.status, 204, result.text);
      };
      if (action === 'review') before('updateTransaction', revoke);
      else if (action === 'continue') before('completeTransaction', revoke);
      else after('getClient', revoke);
      const result = await w.req(action === 'review' ? 'POST' : 'GET', action === 'review' ? `${started.tx.url}/review` : action.includes('continue') ? continueUrl : started.tx.url, {
        headers: { authorization: `Bearer ${accepted.json.transaction_token}` }, ...(action === 'review' ? { json: { decision: 'allow' } } : {}),
      });
      assert.equal(result.status, 401, result.text);
      assert.equal(result.json.error, 'invalid_token');
      assert.equal(result.json.next.url, undefined);
      assert.equal((await w.store.getTransaction(stored.id))?.codeIssued, false);
      assert.equal(await w.store.signupsEver(w.owner.owner_id, client.client_id), 0);
      if (action === 'review') assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined);
    });
  }

  for (const change of ['revoked key', 'expired key', 'disabled Agent', 're-enabled Agent', 'deleted Agent'] as const) {
    test(`${backend}: first assertion racing a ${change} fails without consuming challenge or minting authority`, async (t) => {
      const { w, after } = await setup(t, backend);
      const agent = await w.agent('assertion-race@example.com', change === 'expired key' ? 1 : undefined);
      const other = await w.agent('other-authority@example.com');
      const client = await w.client({ max_signups_per_owner: 1 });
      const started = await w.start(client);
      const original = (await w.store.getTransaction(started.tx.transaction_id))!;
      after('getConsent', async () => {
        if (change === 'expired key') w.advance(1);
        else if (change === 'revoked key') assert.equal((await w.on(1)('DELETE', `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`, { headers: w.cred })).status, 204);
        else if (change === 'deleted Agent') assert.equal((await w.on(1)('DELETE', `/admin/agents/${encodeURIComponent(agent.handle)}`, { headers: w.admin })).status, 204);
        else {
          assert.equal((await w.on(1)('PATCH', `/admin/agents/${encodeURIComponent(agent.handle)}`, { headers: w.admin, json: { enabled: false } })).status, 200);
          if (change === 're-enabled Agent') assert.equal((await w.on(1)('PATCH', `/admin/agents/${encodeURIComponent(agent.handle)}`, { headers: w.admin, json: { enabled: true } })).status, 200);
        }
      });
      const response = await w.assertOn(started.tx, agent);
      assert.equal(response.status, 401, response.text);
      assert.equal(response.json.error, change === 'revoked key' || change === 'expired key' ? 'key_revoked' : 'unknown_key');
      assert.equal(response.json.status, 'awaiting_agent');
      assert.equal(response.json.transaction_token, undefined);
      assert.equal(response.json.next.action, 'assert');
      assert.deepEqual(await w.store.getTransaction(original.id), original);
      assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined);
      // The same challenge can still be asserted by current authority; the rejected request took no quota place.
      const fresh = await w.assertOn(started.tx, other);
      assert.equal(fresh.status, 200, fresh.text);
      assert.equal(fresh.json.status, 'ready');
      assert.equal((await w.store.getTransaction(original.id))?.handle, other.handle);
    });
  }

  for (const initial of [true, false]) {
    for (const silent of [false, true]) {
      test(`${backend}: share_owner ${initial} to ${!initial} during assertion uses current Owner gate${silent ? ' with prompt=none' : ''}`, async (t) => {
        const { w, after } = await setup(t, backend);
        const agent = await w.agent('permission-race@example.com');
        const path = `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`;
        assert.equal((await w.req('PATCH', path, { headers: w.cred, json: { permissions: { share_owner: initial } } })).status, 200);
        const enrollment = (await w.store.getKey(agent.kid, agent.handle))!.enrollment;
        const client = await w.client({ max_signups_per_owner: 1 });
        const started = await w.start(client, { scope: 'openid owner_profile', ...(silent ? { prompt: 'none' } : {}) });
        after('getConsent', async () => {
          assert.equal((await w.on(1)('PATCH', path, { headers: w.cred, json: { permissions: { share_owner: !initial } } })).status, 200);
        });
        const response = await w.assertOn(started.tx, agent);
        assert.equal(response.status, 200, response.text);
        const expected = initial ? silent ? 'denied' : 'awaiting_owner' : 'ready';
        assert.equal(response.json.status, expected, response.text);
        const stored = (await w.store.getTransaction(started.tx.transaction_id))!;
        assert.equal(stored.keyEnrollment, enrollment, 'permission retries cannot change the verified enrollment');
        assert.equal(stored.ownerApprovalOutstanding, initial);
        assert.equal(stored.expiresAt, initial && !silent ? stored.createdAt + DEFAULT_CONSTANTS.T_OWNER : started.tx.expires_at);
        const continueUrl = `${started.tx.url}/continue/${stored.continueSecret}`;
        const continuation = await w.req('GET', continueUrl, { headers: { authorization: `Bearer ${response.json.transaction_token}` } });
        if (initial && !silent) {
          assert.equal(continuation.status, 400, continuation.text);
          assert.equal(continuation.json.error, 'invalid_request');
          assert.equal(stored.codeIssued, false, 'Owner Claims cannot be issued before approval');
          assert.equal(await w.store.signupsEver(w.owner.owner_id, client.client_id), 0);
        } else if (initial) {
          assert.equal(response.json.reason, 'interaction_required');
          assert.equal(continuation.status, 200, continuation.text);
          assert.equal(new URL(continuation.json.redirect).searchParams.get('code'), null);
          assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined, 'silent denial grants no consent');
        } else {
          assert.equal(continuation.status, 200, continuation.text);
          const code = new URL(continuation.json.redirect).searchParams.get('code');
          assert.ok(code);
          const token = await w.token(client, code, started.verifier);
          assert.equal(token.status, 200, token.text);
          assert.equal(decodeJwt(token.json.id_token).owner_name, 'Jane Doe');
        }
      });
    }
  }

  test(`${backend}: a share_owner retry cannot retarget a replacement enrollment of the same key`, async (t) => {
    const { w, after } = await setup(t, backend);
    const agent = await w.agent('permission-replacement@example.com', 1);
    const client = await w.client();
    const started = await w.start(client, { scope: 'openid owner_profile' });
    const original = (await w.store.getTransaction(started.tx.transaction_id))!;
    const originalEnrollment = (await w.store.getKey(agent.kid, agent.handle))!.enrollment;
    after('getConsent', async () => {
      assert.equal((await w.on(1)('PATCH', `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`,
        { headers: w.cred, json: { permissions: { share_owner: true } } })).status, 200);
    });
    after('updateTransaction', async () => {
      w.advance(1);
      const replacement = await w.enroll(agent.handle, agent);
      assert.equal(replacement.en.status, 201, replacement.en.text);
      assert.equal((await replacement.prove()).status, 200);
    });
    const response = await w.assertOn(started.tx, agent);
    assert.equal(response.status, 401, response.text);
    assert.equal(response.json.error, 'unknown_key');
    assert.equal(response.json.transaction_token, undefined);
    assert.notEqual((await w.store.getKey(agent.kid, agent.handle))?.enrollment, originalEnrollment);
    assert.deepEqual(await w.store.getTransaction(original.id), original);
    assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined);
  });

  test(`${backend}: a share_owner retry cannot extend a transaction that reached its original deadline`, async (t) => {
    const { w, after } = await setup(t, backend);
    const agent = await w.agent('permission-deadline@example.com');
    const path = `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`;
    assert.equal((await w.req('PATCH', path, { headers: w.cred, json: { permissions: { share_owner: true } } })).status, 200);
    const client = await w.client();
    const started = await w.start(client, { scope: 'openid owner_profile' });
    const original = (await w.store.getTransaction(started.tx.transaction_id))!;
    w.advance(DEFAULT_CONSTANTS.T_TXN - 1);
    after('getConsent', async () => {
      assert.equal((await w.on(1)('PATCH', path, { headers: w.cred, json: { permissions: { share_owner: false } } })).status, 200);
    });
    after('updateTransaction', async () => { w.advance(1); });
    const response = await w.assertOn(started.tx, agent);
    assert.equal(response.status, 410, response.text);
    assert.equal(response.json.error, 'transaction_expired');
    assert.equal(response.json.status, 'expired');
    assert.equal(response.json.transaction_token, undefined);
    assert.deepEqual(await w.store.getTransaction(original.id), original);
    assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined);
  });

  test(`${backend}: transaction expiry takes precedence over a signed assertion window that expires during verification`, async (t) => {
    const { w, after } = await setup(t, backend);
    const agent = await w.agent('window@example.com');
    const client = await w.client();
    const started = await w.start(client);
    const original = await w.store.getTransaction(started.tx.transaction_id);
    w.advance(DEFAULT_CONSTANTS.T_TXN - 1);
    after('getKey', async () => { w.advance(DEFAULT_CONSTANTS.T_ASSERT); });
    const response = await w.assertOn(started.tx, agent);
    assert.equal(response.status, 410, response.text);
    assert.equal(response.json.error, 'transaction_expired');
    assert.equal(response.json.status, 'expired');
    assert.equal(response.json.next.url, undefined);
    assert.deepEqual(await w.store.getTransaction(started.tx.transaction_id), original);
  });

  for (const outcome of ['ready', 'awaiting_owner', 'denied'] as const) {
    test(`${backend}: assertion planned as ${outcome} crossing the transaction deadline returns 410 without authority or consent`, async (t) => {
      const { w, after } = await setup(t, backend);
      const agent = await w.agent('deadline@example.com');
      const other = await w.agent('after-deadline@example.com');
      const client = await w.client({ max_signups_per_owner: 1 });
      const started = await w.start(client, outcome === 'awaiting_owner' ? { scope: 'openid owner_profile' } : outcome === 'denied' ? { prompt: 'none' } : {});
      const original = (await w.store.getTransaction(started.tx.transaction_id))!;
      w.advance(DEFAULT_CONSTANTS.T_TXN - 1);
      after('getConsent', async () => { w.advance(1); });
      const response = await w.assertOn(started.tx, agent, 0, { accept_disclosure: outcome !== 'denied' });
      assert.equal(response.status, 410, response.text);
      assert.equal(response.json.error, 'transaction_expired');
      assert.equal(response.json.status, 'expired');
      assert.equal(response.json.transaction_token, undefined);
      assert.equal(response.json.next.url, undefined);
      assert.deepEqual(await w.store.getTransaction(original.id), original);
      assert.equal(await w.store.getConsent(agent.handle, client.client_id), undefined);
      const anonymous = await w.req('GET', started.tx.url);
      assert.equal(anonymous.json.status, 'expired');
      assert.equal(anonymous.json.expires_at, original.expiresAt);
      assert.equal((await w.ready(client, other)).tx.status, 'ready', 'no rejected assertion quota reservation remains');
    });
  }
}
