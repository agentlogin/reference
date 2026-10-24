import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore, SQLiteStore, type AgentKey, type Account } from '../src/index.js';
import { sha256 } from '../src/util.js';
import { world } from './fixtures.js';
import { hookable, snapshotting } from './stores.js';

type World = Awaited<ReturnType<typeof world>>;
type Backend = 'memory' | 'sqlite';

async function withManagementWorld(backend: Backend, run: (w: World, hooks: ReturnType<typeof hookable>) => Promise<void>) {
  const directory = backend === 'sqlite' ? mkdtempSync(join(tmpdir(), 'agentlogin-management-auth-')) : undefined;
  const raw = directory ? new SQLiteStore(join(directory, 'issuer.sqlite')) : new MemoryStore();
  try {
    const hooks = hookable(snapshotting(raw));
    await run(await world({ store: hooks.store }), hooks);
  } finally {
    if (raw instanceof SQLiteStore) raw.close();
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
}

async function delegate(w: World, handle: string) {
  const response = await w.req('POST', '/admin/credentials', {
    headers: w.admin, json: { owner_id: w.owner.owner_id, kind: 'delegated', handle },
  });
  assert.equal(response.status, 201, response.text);
  const credential = response.json.credential as string;
  return { hash: sha256(credential), headers: { authorization: `Bearer ${credential}` } };
}

async function signIn(w: World, agent: Awaited<ReturnType<World['agent']>>) {
  const client = await w.client();
  const code = await w.codeFor(client, agent);
  const token = await w.token(client, code.code, code.verifier);
  assert.equal(token.status, 200, token.text);
  const accessToken = token.json.access_token as string;
  assert.equal((await w.userinfo(accessToken)).status, 200);
  return { clientId: client.client_id, accessToken };
}

for (const backend of ['memory', 'sqlite'] as const) {
  test(`${backend}: delayed delegated management cannot reach a replacement Agent with the same owner and handle`, async (t) => {
    const operations = [
      ['list keys', 'GET', 'keys'], ['get key', 'GET', 'key'], ['list accounts', 'GET', 'accounts'],
      ['rename key', 'PATCH', 'key'], ['revoke key', 'DELETE', 'key'],
    ] as const;
    for (const [name, method, resource] of operations) {
      await t.test(name, () => withManagementWorld(backend, async (w, hooks) => {
        const original = await w.agent('scout@example.com');
        const originalSub = (await w.store.getAgent(original.handle))!.sub;
        const delegated = await delegate(w, original.handle);
        const replacement = { handle: original.handle, ...await w.newKey() };
        const base = `/agents/${encodeURIComponent(original.handle)}`;
        let replacementSub = '';
        let accessToken = '';
        let clientId = '';
        let keyBefore: AgentKey | undefined;
        let accountsBefore: Account[] = [];
        hooks.after('resolveManagement', async () => {
          assert.equal((await w.req('DELETE', `/admin/agents/${encodeURIComponent(original.handle)}`, { headers: w.admin })).status, 204);
          assert.equal((await w.req('POST', '/admin/agents', {
            headers: w.admin, json: { handle: original.handle, owner_id: w.owner.owner_id },
          })).status, 201);
          replacementSub = (await w.store.getAgent(original.handle))!.sub;
          assert.notEqual(replacementSub, originalSub);
          const enrollment = await w.enroll(replacement.handle, replacement);
          assert.equal(enrollment.en.status, 201, enrollment.en.text);
          assert.equal((await enrollment.prove()).status, 200);
          ({ accessToken, clientId } = await signIn(w, replacement));
          keyBefore = await w.store.getKey(replacement.kid, replacement.handle);
          accountsBefore = await w.store.listAccounts(replacement.handle);
          assert.equal(keyBefore?.status, 'active');
          assert.equal(accountsBefore.length, 1);
        });

        const path = resource === 'key' ? `${base}/keys/${encodeURIComponent(replacement.kid)}` : `${base}/${resource}`;
        const stale = await w.req(method, path, {
          headers: delegated.headers, ...(method === 'PATCH' ? { json: { name: 'stale rename' } } : {}),
        });
        assert.equal(stale.status, 404, stale.text);
        assert.equal(stale.json.error, 'not_found');
        assert.ok(replacementSub, 'the request was paused after its authorization snapshot');
        for (const replacementValue of [replacementSub, replacement.kid, clientId]) {
          assert.equal(stale.text.includes(replacementValue), false, 'the error must not expose replacement records');
        }
        assert.deepEqual(await w.store.getKey(replacement.kid, replacement.handle), keyBefore);
        assert.deepEqual(await w.store.listAccounts(replacement.handle), accountsBefore);
        assert.equal((await w.userinfo(accessToken)).status, 200, 'stale management must not invalidate replacement tokens');
        const freshKeys = await w.req('GET', `${base}/keys`, { headers: w.cred });
        assert.equal(freshKeys.status, 200, freshKeys.text);
        assert.equal(freshKeys.json.keys[0].kid, replacement.kid);
        const freshAccounts = await w.req('GET', `${base}/accounts`, { headers: w.cred });
        assert.equal(freshAccounts.status, 200, freshAccounts.text);
        assert.equal(freshAccounts.json.accounts[0].client_id, clientId);
        const freshDelegated = await w.req('GET', `${base}/keys`, { headers: delegated.headers });
        assert.equal(freshDelegated.status, 401, freshDelegated.text);
        assert.equal(freshDelegated.json.error, 'invalid_token');
      }));
    }
  });

  test(`${backend}: key mutations recheck a delegated credential removed after the key read`, async (t) => {
    for (const method of ['PATCH', 'DELETE'] as const) {
      await t.test(method, () => withManagementWorld(backend, async (w, hooks) => {
        const agent = await w.agent('scout@example.com');
        const delegated = await delegate(w, agent.handle);
        const { accessToken } = await signIn(w, agent);
        const keyBefore = await w.store.getKey(agent.kid, agent.handle);
        let removed = false;
        hooks.after('readManagementKeys', async () => {
          await w.store.deleteCredential(delegated.hash);
          removed = true;
        });
        const path = `/agents/${encodeURIComponent(agent.handle)}/keys/${encodeURIComponent(agent.kid)}`;
        const stale = await w.req(method, path, {
          headers: delegated.headers, ...(method === 'PATCH' ? { json: { name: 'stale rename' } } : {}),
        });
        assert.equal(removed, true);
        assert.equal(stale.status, 404, stale.text);
        assert.equal(stale.json.error, 'not_found');
        assert.deepEqual(await w.store.getKey(agent.kid, agent.handle), keyBefore);
        assert.equal((await w.userinfo(accessToken)).status, 200);
        const freshDelegated = await w.req('GET', path, { headers: delegated.headers });
        assert.equal(freshDelegated.status, 401, freshDelegated.text);
        assert.equal(freshDelegated.json.error, 'invalid_token');
      }));
    }
  });

  test(`${backend}: a downgraded Owner session cannot grant share_owner after the key read`, () => withManagementWorld(backend, async (w, hooks) => {
    const agent = await w.agent('scout@example.com');
    const { accessToken } = await signIn(w, agent);
    const keyBefore = await w.store.getKey(agent.kid, agent.handle);
    const ownerCredential = await w.store.getCredential(sha256(w.owner.credential));
    assert.ok(ownerCredential);
    assert.equal(ownerCredential.sessionAuth, 'passkey');
    assert.equal(keyBefore?.permissions.share_owner, false);
    let downgraded = false;
    hooks.after('readManagementKeys', async () => {
      await w.store.putCredential({ ...ownerCredential, sessionAuth: 'email_only' });
      downgraded = true;
    });
    const path = `/agents/${encodeURIComponent(agent.handle)}/keys/${encodeURIComponent(agent.kid)}`;
    const json = { name: 'stale rename', permissions: { share_owner: true } };
    const stale = await w.req('PATCH', path, { headers: w.cred, json });
    assert.equal(downgraded, true);
    assert.equal(stale.status, 404, stale.text);
    assert.equal(stale.json.error, 'not_found');
    assert.deepEqual(await w.store.getKey(agent.kid, agent.handle), keyBefore, 'neither the name nor permission can change');
    assert.equal((await w.userinfo(accessToken)).status, 200);
    const fresh = await w.req('PATCH', path, { headers: w.cred, json });
    assert.equal(fresh.status, 403, fresh.text);
    assert.equal(fresh.json.error, 'insufficient_permission');
  }));
}
