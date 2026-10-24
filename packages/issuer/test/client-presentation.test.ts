import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createIssuer, MemoryStore, SQLiteStore, type Store } from '../src/index.js';
import { world } from './fixtures.js';

function storage(t: TestContext, adapter: 'memory' | 'sqlite'): Store {
  if (adapter === 'memory') return new MemoryStore();
  const directory = mkdtempSync(join(tmpdir(), 'agentlogin-presentation-'));
  const store = new SQLiteStore(join(directory, 'issuer.sqlite'));
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  return store;
}

for (const adapter of ['memory', 'sqlite'] as const) {
  for (const phase of ['assertion', 'review', 'owner'] as const) {
    test(`${adapter}: ${phase} accepts only the transaction's displayed client metadata`, async (t) => {
      const store = storage(t, adapter);
      const w = await world({ store });
      const agent = await w.agent('presentation@example.com');
      const client = await w.client({ client_name: 'Displayed name', policy_uri: 'https://rp.example/policy-a' });
      const started = await w.start(client, { scope: phase === 'owner' ? 'openid owner_email' : 'openid profile' });
      let pending = started.tx;
      if (phase !== 'assertion') {
        pending = (await w.assertOn(pending, agent, 0, { accept_disclosure: phase === 'owner' })).json;
        assert.equal(pending.status, phase === 'owner' ? 'awaiting_owner' : 'awaiting_consent');
      }
      const current = (await store.getClient(client.client_id))!;
      await store.putClient({ ...current, clientName: 'Changed name', policyUri: 'https://rp.example/policy-b', tosUri: undefined });
      const polled = await w.req('GET', pending.url);
      assert.equal(polled.json.client.client_name, 'Displayed name');
      assert.equal(polled.json.client.policy_uri, 'https://rp.example/policy-a');
      assert.equal(polled.json.client.tos_uri, 'https://rp.example/tos');
      assert.match((await w.req('GET', `${pending.url}/wait`)).text, /Displayed name/);
      if (phase === 'assertion') {
        const accepted = await w.assertOn(pending, agent);
        assert.equal(accepted.json.status, 'ready', accepted.text);
        assert.equal(accepted.json.client.policy_uri, 'https://rp.example/policy-a');
      } else if (phase === 'review') {
        const accepted = await w.req('POST', pending.next.url, { json: { decision: 'allow' }, headers: { authorization: `Bearer ${pending.transaction_token}` } });
        assert.equal(accepted.json.status, 'ready', accepted.text);
        assert.equal(accepted.json.client.policy_uri, 'https://rp.example/policy-a');
      } else {
        const ownerView = await w.req('GET', `/owner/transactions/${pending.transaction_id}`, { headers: w.cred });
        assert.equal(ownerView.json.client.client_name, 'Displayed name');
        assert.equal(ownerView.json.client.policy_uri, 'https://rp.example/policy-a');
        const accepted = await w.req('POST', `/owner/transactions/${pending.transaction_id}/decision`, { json: { decision: 'approve' }, headers: w.cred });
        assert.equal(accepted.json.status, 'ready', accepted.text);
      }
      assert.equal((await store.getConsent(agent.handle, client.client_id))?.policyUri, 'https://rp.example/policy-a');
      const pin = (await store.getTransaction(pending.transaction_id))!.clientPresentation!;
      assert.equal('clientSecretHash' in pin, false);
      assert.equal('tokenEndpointAuthMethod' in pin, false);
      assert.equal('maxSignupsPerOwner' in pin, false);
      const later = await w.assertOn((await w.start(client, { scope: 'openid' })).tx, agent, 0, { accept_disclosure: false });
      assert.equal(later.json.status, 'awaiting_consent');
      assert.equal(later.json.consent_reason, 'material_change');
      assert.equal(later.json.client.policy_uri, 'https://rp.example/policy-b');
    });
  }

  test(`${adapter}: absent presentation fields remain absent and live review policy is enforced`, async (t) => {
    const store = storage(t, adapter);
    const w = await world({ store });
    const agent = await w.agent('absent@example.com');
    const client = await w.client({ client_name: undefined, tos_uri: undefined, policy_uri: undefined });
    const started = await w.start(client, { scope: 'openid' });
    await store.putClient({ ...(await store.getClient(client.client_id))!, clientName: 'Later name', policyUri: 'https://rp.example/later', requireReview: true });
    const accepted = await w.assertOn(started.tx, agent);
    assert.equal(accepted.json.status, 'awaiting_consent');
    assert.equal(accepted.json.consent_reason, 'policy');
    assert.equal(accepted.json.client.client_name, undefined);
    assert.equal(accepted.json.client.policy_uri, undefined);
  });

  test(`${adapter}: startup cancels legacy transactions once without backfilling or renewing retention`, async (t) => {
    const store = storage(t, adapter);
    const w = await world({ store });
    const agent = await w.agent('legacy@example.com');
    const client = await w.client();
    const ready = await w.ready(client, agent);
    const source = (await store.getTransaction(ready.tx.transaction_id))!;
    const { clientPresentation: _pin, ...legacy } = { ...source, id: 'legacy-ready' };
    await store.insertTransaction(legacy);
    await store.insertTransaction({ ...legacy, id: 'legacy-expired', expiresAt: source.createdAt + 1 });
    let now = source.createdAt + 10;
    const options = { store, issuer: 'https://issuer.test', handleDomains: ['example.com'], now: () => now };
    await createIssuer(options);
    const cancelled = (await store.getTransaction(legacy.id))!;
    assert.equal(cancelled.status, 'denied');
    assert.equal(cancelled.reason, 'access_denied');
    assert.equal(cancelled.terminalAt, now);
    assert.equal(cancelled.clientPresentation, undefined);
    assert.equal((await store.getTransaction('legacy-expired'))?.terminalAt, source.createdAt + 1);
    assert.equal((await store.getTransaction('legacy-expired'))?.status, 'expired');
    assert.equal((await store.getTransaction(source.id))?.status, 'ready');
    now += 20;
    await createIssuer(options);
    assert.deepEqual(await store.getTransaction(legacy.id), cancelled);
    assert.deepEqual(await store.listLegacyTransactions(256), []);
  });
}

test('Open Client cache refresh cannot change an existing transaction review', async (t) => {
  let policy = 'https://rp.example/policy-a';
  let origin: string;
  let fetches = 0;
  const server = createServer((_req, res) => {
    fetches += 1;
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ client_id: `${origin}/client.json`, redirect_uris: ['https://rp.example/cb'],
      token_endpoint_auth_method: 'none', policy_uri: policy }));
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const w = await world({ insecureClients: true });
  const agent = await w.agent('refresh@example.com');
  const client = { client_id: `${origin}/client.json`, client_secret: '', redirect_uri: 'https://rp.example/cb' };
  const pending = (await w.assertOn((await w.start(client)).tx, agent, 0, { accept_disclosure: false })).json;
  assert.equal(pending.status, 'awaiting_consent');
  assert.equal(pending.client.policy_uri, policy);
  policy = 'https://rp.example/policy-b';
  const next = await w.start(client);
  assert.equal(fetches, 2);
  assert.equal(next.tx.client.policy_uri, policy);
  const allowed = await w.req('POST', pending.next.url, { json: { decision: 'allow' }, headers: { authorization: `Bearer ${pending.transaction_token}` } });
  assert.equal(allowed.json.status, 'ready', allowed.text);
  assert.equal(allowed.json.client.policy_uri, 'https://rp.example/policy-a');
  assert.equal((await w.store.getConsent(agent.handle, client.client_id))?.policyUri, 'https://rp.example/policy-a');
  const newTerms = await w.assertOn(next.tx, agent, 0, { accept_disclosure: false });
  assert.equal(newTerms.json.status, 'awaiting_consent');
  assert.equal(newTerms.json.consent_reason, 'material_change');
});
