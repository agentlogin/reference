import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStore, SQLiteStore, type Store } from '../src/index.js';
import { world } from './fixtures.js';

for (const adapter of ['memory', 'sqlite'] as const) {
  test(`${adapter}: code replay revokes existing tokens atomically before handler cleanup`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentlogin-replay-'));
    const filename = join(directory, 'issuer.sqlite');
    const store: Store = adapter === 'sqlite' ? new SQLiteStore(filename) : new MemoryStore();
    try {
      const w = await world({ store });
      const agent = await w.agent('replay@example.com');
      const client = await w.client();
      const code = await w.codeFor(client, agent);
      const issued = await w.token(client, code.code, code.verifier);
      assert.equal(issued.status, 200);
      const tokenHash = createHash('sha256').update(issued.json.access_token).digest('base64url');
      assert.equal((await store.getAccessToken(tokenHash))!.revoked, false);

      // Stop at the first durable replay write, as if the request process died before any later handler cleanup.
      // The existing token must already be revoked by the same operation that recorded the replay.
      const codeHash = createHash('sha256').update(code.code).digest('base64url');
      assert.equal(await store.redeemCode(codeHash, Math.floor(Date.now() / 1000)), 'used');
      assert.equal((await store.getCode(codeHash))!.replayed, true);
      assert.equal((await store.getAccessToken(tokenHash))!.revoked, true);
      assert.equal((await w.userinfo(issued.json.access_token)).status, 401);

      if (adapter === 'sqlite') {
        (store as SQLiteStore).close();
        const reopened = new SQLiteStore(filename);
        try {
          assert.equal((await reopened.getCode(codeHash))!.replayed, true);
          assert.equal((await reopened.getAccessToken(tokenHash))!.revoked, true, 'revocation survives a restart without cleanup');
        } finally { reopened.close(); }
      }
    } finally {
      if (store instanceof SQLiteStore) store.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
}
