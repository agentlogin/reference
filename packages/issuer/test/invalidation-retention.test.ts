import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStore, type Store } from '../src/index.js';
import { DEFAULT_CONSTANTS } from '../src/constants.js';
import { SQLiteStore } from '../src/sqlite-store.js';
import { world } from './fixtures.js';

async function setup(t: TestContext, backend: 'memory' | 'sqlite') {
  let stores: [Store, Store];
  if (backend === 'sqlite') {
    const dir = mkdtempSync(join(tmpdir(), 'agentlogin-retention-'));
    const first = new SQLiteStore(join(dir, 'issuer.sqlite'));
    const second = new SQLiteStore(join(dir, 'issuer.sqlite'));
    stores = [first, second];
    t.after(() => { first.close(); second.close(); rmSync(dir, { recursive: true, force: true }); });
  } else {
    const store = new MemoryStore();
    stores = [store, store];
  }
  return world({ store: stores[0], stores, instances: 2 });
}

for (const backend of ['memory', 'sqlite'] as const) {
  for (const change of ['revoke key', 'disable agent', 'delete agent', 'disable account'] as const) {
    test(`${backend}: ${change} preserves transaction expiry and retention`, async (t) => {
      const w = await setup(t, backend);
      const agent = await w.agent('scout@example.com');
      const client = await w.client();
      if (change === 'disable account') await w.codeFor(client, agent);

      const old = await w.ready(client, agent);
      w.advance(86400);
      const recent = await w.ready(client, agent);
      // Invalidation occurs after expiry, while this transaction is still retained. Using a nonzero offset
      // distinguishes the original expiry from an incorrectly reset terminal timestamp.
      const afterExpiry = 7;
      w.advance(DEFAULT_CONSTANTS.T_TXN + afterExpiry);
      const live = await w.ready(client, agent);
      const read = (tx: typeof old.tx) => w.req('GET', tx.url);
      const hidden = await read(old.tx);
      assert.equal(hidden.status, 404, hidden.text);
      assert.equal(hidden.json.error, 'invalid_transaction');
      const retained = await read(recent.tx);
      assert.equal(retained.status, 200, retained.text);
      assert.equal(retained.json.status, 'expired');
      // Reads apply effective expiry without rewriting the stored ready status: reproduce the state that
      // originally let a subsequent lifecycle change reset retention and disclose the old transaction.
      assert.equal((await w.store.getTransaction(old.tx.transaction_id))?.status, 'ready');
      assert.equal((await w.store.getTransaction(recent.tx.transaction_id))?.status, 'ready');

      const other = w.on(1);
      const handle = encodeURIComponent(agent.handle);
      let response;
      if (change === 'revoke key') {
        response = await other('DELETE', `/agents/${handle}/keys/${encodeURIComponent(agent.kid)}`, { headers: w.cred });
      } else if (change === 'disable agent') {
        response = await other('PATCH', `/admin/agents/${handle}`, { json: { enabled: false }, headers: w.admin });
      } else if (change === 'delete agent') {
        response = await other('DELETE', `/admin/agents/${handle}`, { headers: w.admin });
      } else {
        response = await other('PATCH', `/agents/${handle}/accounts/${encodeURIComponent(client.client_id)}`, {
          json: { status: 'disabled' }, headers: w.cred,
        });
      }
      assert.equal(response.status, change === 'revoke key' || change === 'delete agent' ? 204 : 200, response.text);

      const stillHidden = await read(old.tx);
      assert.equal(stillHidden.status, 404, 'a lifecycle change must not make an expired transaction readable again');
      assert.equal(stillHidden.json.error, 'invalid_transaction');
      for (const { tx } of [old, recent]) {
        const stored = (await w.store.getTransaction(tx.transaction_id))!;
        assert.equal(stored.status, 'expired');
        assert.equal(stored.terminalAt, tx.expires_at, 'retention starts at the original expiry');
        assert.equal(stored.reason, undefined);
        assert.equal(stored.codeIssued, false);
        assert.equal(stored.challenge, undefined);
      }
      const afterChange = await read(recent.tx);
      assert.equal(afterChange.status, 200, afterChange.text);
      assert.equal(afterChange.json.status, 'expired');
      assert.equal(afterChange.json.reason, undefined);
      const continuation = await w.cont(recent.tx);
      if (change === 'revoke key') {
        assert.equal(continuation.status, 401, continuation.text);
        assert.equal(continuation.json.error, 'invalid_token');
        assert.equal(continuation.json.next.url, undefined);
      } else {
        assert.equal(continuation.status, 200, continuation.text);
        const redirect = new URL(continuation.json.redirect);
        assert.equal(redirect.searchParams.get('code'), null, 'the expired transaction cannot issue a code');
        assert.equal(redirect.searchParams.get('error'), 'access_denied');
        assert.equal(redirect.searchParams.get('error_description'), 'transaction_expired');
      }

      const invalidated = (await w.store.getTransaction(live.tx.transaction_id))!;
      assert.equal(invalidated.status, 'denied', 'the same lifecycle change must still invalidate a live transaction');
      assert.equal(invalidated.reason, change === 'revoke key' ? 'key_revoked' : 'access_denied');
      assert.equal(invalidated.terminalAt, invalidated.createdAt);
      assert.equal(invalidated.codeIssued, false);
      assert.equal(await w.store.signupsEver(w.owner.owner_id, client.client_id), change === 'disable account' ? 1 : 0);

      w.advance(DEFAULT_CONSTANTS.T_RETAIN - afterExpiry);
      assert.equal((await read(recent.tx)).status, 200, 'the original retention boundary remains readable');
      w.advance(1);
      assert.equal((await read(recent.tx)).status, 404, 'retention ends on its original schedule');
    });
  }
}
