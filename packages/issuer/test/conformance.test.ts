import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore, SQLiteStore } from '../src/index.js';
import { snapshotting } from './stores.js';
import { conformanceRun } from './conformance-fixtures.js';

test('reference issuer passes the conformance harness', () => conformanceRun());
// The same run against a store with the timing and copy semantics of a database: the in-memory store hides races.
test('reference issuer passes the conformance harness with a store that behaves like a database', () => conformanceRun(snapshotting(new MemoryStore())));
test('reference issuer passes the conformance harness with durable SQLite storage', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agentlogin-conformance-'));
  const store = new SQLiteStore(join(directory, 'issuer.db'));
  try { await conformanceRun(store); }
  finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});
