import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStore, SQLiteStore, type Store } from '../src/index.js';
import type { Client } from '../src/store.js';
import { world } from './fixtures.js';

async function setup(t: TestContext, adapter: 'memory' | 'sqlite', priorScope = 'owner_email') {
  let store: Store = new MemoryStore();
  if (adapter === 'sqlite') {
    const directory = mkdtempSync(join(tmpdir(), 'agentlogin-consent-'));
    const sqlite = new SQLiteStore(join(directory, 'issuer.sqlite'));
    store = sqlite;
    t.after(() => { sqlite.close(); rmSync(directory, { recursive: true, force: true }); });
  }
  const w = await world({ store });
  const agent = await w.agent('consent@example.com');
  const permission = await w.req('PATCH', `/agents/${encodeURIComponent(agent.handle)}/keys/${agent.kid}`, {
    json: { permissions: { share_owner: true } }, headers: w.cred,
  });
  assert.equal(permission.status, 200, permission.text);
  const client = await w.client();
  const initial = await w.assertOn((await w.start(client, { scope: `openid ${priorScope}` })).tx, agent);
  assert.equal(initial.json.status, 'ready', initial.text);
  assert.equal((await w.cont(initial.json)).status, 200);
  return { w, store, agent, client };
}

const materialChanges: { name: string; priorScope?: string; update: (client: Client) => Client }[] = [
  { name: 'redirect host', update: (client) => ({ ...client, redirectUris: ['https://new-rp.example/cb'] }) },
  { name: 'client name', update: (client) => ({ ...client, clientName: 'New name' }) },
  { name: 'terms URI', update: (client) => ({ ...client, tosUri: 'https://rp.example/new-terms' }) },
  { name: 'policy URI', update: (client) => ({ ...client, policyUri: 'https://rp.example/new-policy' }) },
  { name: 'removed client name', update: (client) => ({ ...client, clientName: undefined }) },
  // Owner scopes require both legal URIs at authorization, so use profile to test removal independently.
  { name: 'removed terms URI', priorScope: 'profile', update: (client) => ({ ...client, tosUri: undefined }) },
  { name: 'removed policy URI', priorScope: 'profile', update: (client) => ({ ...client, policyUri: undefined }) },
];

for (const adapter of ['memory', 'sqlite'] as const) {
  for (const change of materialChanges) {
    test(`${adapter}: accepting narrower consent after ${change.name} changes does not carry over old scopes`, async (t) => {
      const priorScope = change.priorScope ?? 'owner_email';
      const { w, store, agent, client } = await setup(t, adapter, priorScope);
      const changed = change.update((await store.getClient(client.client_id))!);
      await store.putClient(changed);
      const updatedClient = { ...client, redirect_uri: changed.redirectUris[0]! };

      const accepted = await w.assertOn((await w.start(updatedClient, { scope: 'openid' })).tx, agent);
      assert.equal(accepted.json.status, 'ready', accepted.text);
      assert.equal((await w.cont(accepted.json)).status, 200);

      const later = await w.assertOn((await w.start(updatedClient, { scope: `openid ${priorScope}` })).tx, agent, 0, { accept_disclosure: false });
      assert.equal(later.json.status, 'awaiting_consent', `${priorScope} requires consent under the changed terms`);
      assert.equal(later.json.consent_reason, 'material_change');
      assert.deepEqual((await store.getConsent(agent.handle, client.client_id))?.scopes, ['openid']);
    });
  }

  test(`${adapter}: unchanged material metadata preserves previously accepted scopes`, async (t) => {
    const { w, store, agent, client } = await setup(t, adapter);
    const original = (await store.getClient(client.client_id))!;
    const callback = new URL(client.redirect_uri);
    callback.pathname = '/another-callback';
    // The callback host, name and legal metadata still describe the same consent terms.
    await store.putClient({ ...original, redirectUris: [callback.href], logoUri: 'https://rp.example/new-logo.png' });
    const updatedClient = { ...client, redirect_uri: callback.href };
    const accepted = await w.assertOn((await w.start(updatedClient, { scope: 'openid' })).tx, agent);
    assert.equal(accepted.json.status, 'ready', accepted.text);
    assert.equal((await w.cont(accepted.json)).status, 200);

    const later = await w.assertOn((await w.start(updatedClient, { scope: 'openid owner_email' })).tx, agent, 0, { accept_disclosure: false });
    assert.equal(later.json.status, 'ready', later.text);
    assert.deepEqual((await store.getConsent(agent.handle, client.client_id))?.scopes, ['openid', 'owner_email']);
  });
}
