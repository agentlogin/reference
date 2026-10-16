import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixture, quote, skipPostgres } from './helpers.js';

test('host authorization expiry at commit rolls back writes already performed by the transaction', { skip: skipPostgres }, async (t) => {
  let armed = false;
  let advance!: () => Promise<void>;
  const expired = new Error('host session expired');
  const f = await fixture(t, {
    onCheckpoint: async ({ operation, phase }) => {
      if (armed && operation === 'host approval' && phase === 'beforeCommit') await advance();
    },
    beforeMutationCommit: async (s) => {
      if (armed && await s.now() >= 1_700_000_005) throw expired;
    },
  });
  advance = () => f.advance(5);
  await f.admin.query(`CREATE TABLE ${quote(f.schema)}.host_probe (id text PRIMARY KEY)`);
  armed = true;
  await assert.rejects(f.store.db.mutate('host approval', async (s) => {
    await s.query(`INSERT INTO ${quote(f.schema)}.host_probe VALUES ('attempt')`);
    assert.equal((await s.query(`SELECT * FROM ${quote(f.schema)}.host_probe`)).rowCount, 1);
    return 'approved';
  }), (e) => e === expired);
  assert.equal((await f.admin.query(`SELECT * FROM ${quote(f.schema)}.host_probe`)).rowCount, 0);
});
