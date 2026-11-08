import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import { MemoryStore, SQLiteStore } from '../src/index.js';
import { fixture as postgresFixture, skipPostgres } from '../../store-postgres/test/helpers.js';
import { world } from './fixtures.js';

type Adapter = 'memory' | 'sqlite' | 'postgres';

async function replayWorld(t: TestContext, adapter: Adapter) {
  if (adapter === 'postgres') {
    const { store, peer } = await postgresFixture(t, { realClock: true });
    return world({ store, stores: [store, peer], instances: 2 });
  }
  if (adapter === 'sqlite') {
    const directory = await mkdtemp(join(tmpdir(), 'agentlogin-replay-binding-'));
    const store = new SQLiteStore(join(directory, 'issuer.sqlite'));
    const peer = new SQLiteStore(join(directory, 'issuer.sqlite'));
    t.after(async () => {
      store.close();
      peer.close();
      await rm(directory, { recursive: true, force: true });
    });
    return world({ store, stores: [store, peer], instances: 2 });
  }
  const store = new MemoryStore();
  return world({ store, stores: [store, store], instances: 2 });
}

for (const adapter of ['memory', 'sqlite', 'postgres'] as const) {
  for (const wrongBinding of ['PKCE', 'client', 'redirect'] as const) {
    test(`${adapter}: a used-code replay with wrong ${wrongBinding} preserves its token; a proven replay revokes it`, {
      skip: adapter === 'postgres' ? skipPostgres : false,
    }, async (t) => {
      const w = await replayWorld(t, adapter);
      const agent = await w.agent('replay-binding@example.com');
      const client = await w.client();
      const code = await w.codeFor(client, agent);
      const issued = await w.token(client, code.code, code.verifier);
      assert.equal(issued.status, 200);
      assert.equal(typeof issued.json.access_token, 'string');
      const accessToken = issued.json.access_token as string;
      const userinfo = (instance: number) => w.on(instance)('GET', '/userinfo', {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const before = await userinfo(1);
      assert.equal(before.status, 200, 'the first exchange must produce a token accepted by the other instance');
      assert.equal(typeof before.json.sub, 'string');

      // The code has already been redeemed. Change exactly one proof binding;
      // another valid client authenticates with its own real secret, rather than
      // merely failing client authentication before the code is examined.
      let replayClient = client;
      let replayVerifier = code.verifier;
      if (wrongBinding === 'PKCE') {
        replayVerifier = 'z'.repeat(43);
        assert.notEqual(replayVerifier, code.verifier);
      } else if (wrongBinding === 'client') {
        replayClient = { ...await w.client(), redirect_uri: client.redirect_uri };
        assert.notEqual(replayClient.client_id, client.client_id);
      } else {
        replayClient = { ...client, redirect_uri: `${client.redirect_uri}?wrong=1` };
      }
      const unproven = await w.token(replayClient, code.code, replayVerifier, 1);
      assert.equal(unproven.status, 400);
      assert.equal(unproven.json.error, 'invalid_grant');
      for (const field of ['access_token', 'id_token', 'refresh_token']) {
        assert.equal(unproven.json[field], undefined, `rejected replay must not return ${field}`);
      }
      for (const instance of [0, 1]) {
        const stillValid = await userinfo(instance);
        assert.equal(stillValid.status, 200, 'a replay without the client proof must not revoke the legitimate token');
        assert.equal(stillValid.json.sub, before.json.sub);
      }

      // Prove the real bindings for the exact same used code. This must still
      // fail redemption, but now the issuer can revoke that code's token set.
      const proven = await w.token(client, code.code, code.verifier, 1);
      assert.equal(proven.status, 400);
      assert.equal(proven.json.error, 'invalid_grant');
      for (const field of ['access_token', 'id_token', 'refresh_token']) {
        assert.equal(proven.json[field], undefined, `used code must not return ${field}`);
      }
      for (const instance of [0, 1]) {
        const revoked = await userinfo(instance);
        assert.equal(revoked.status, 401, 'a proven replay must invalidate the original token on both instances');
        assert.equal(revoked.json.error, 'invalid_token');
      }
    });
  }
}
