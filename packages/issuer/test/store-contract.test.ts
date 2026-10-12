import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore } from '../src/store.js';
import { SQLiteStore } from '../src/sqlite-store.js';
import { registerStoreContract } from './store-contract.js';

for (const backend of ['memory', 'sqlite'] as const) {
  registerStoreContract(backend, async () => {
    let clock = 1_700_000_000;
    const directory = backend === 'sqlite' ? mkdtempSync(join(tmpdir(), 'agentlogin-contract-')) : undefined;
    const store = directory ? new SQLiteStore(join(directory, 'issuer.sqlite')) : new MemoryStore();
    const peer = directory ? new SQLiteStore(join(directory, 'issuer.sqlite')) : store;
    return {
      store, peer, now: () => clock, advance: async (seconds) => { clock += seconds; },
      close: () => {
        if (store instanceof SQLiteStore) store.close();
        if (peer instanceof SQLiteStore) peer.close();
        if (directory) rmSync(directory, { recursive: true, force: true });
      },
    };
  });
}
