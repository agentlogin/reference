import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore, SQLiteStore, type Store } from '../src/index.js';
import { world } from './fixtures.js';

for (const backend of ['memory', 'sqlite'] as const) {
  for (const delayed of [false, true]) test(`${backend}: pending key expiry ${delayed ? 'during activation' : 'before proof'} is reported as key_revoked`, async (t) => {
    const directory = mkdtempSync(join(tmpdir(), 'agentlogin-pending-expiry-'));
    const store = backend === 'memory' ? new MemoryStore() : new SQLiteStore(join(directory, 'issuer.sqlite'));
    t.after(() => { if (store instanceof SQLiteStore) store.close(); rmSync(directory, { recursive: true, force: true }); });
    let expire = () => {};
    let armed = false;
    const wrapped = new Proxy(store, { get(target, property) {
      const value = Reflect.get(target, property, target);
      if (property === 'activateKey') return async (...args: Parameters<Store['activateKey']>) => {
        if (armed) {
          armed = false;
          expire();
          // Models an adapter that resumes after a wait and checks its fresh authoritative time.
          args[3] += 1;
        }
        return target.activateKey(...args);
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const w = await world({ store: wrapped });
    const handle = 'pending-expiry@example.com';
    assert.equal((await w.req('POST', '/admin/agents', { headers: w.admin, json: { handle, owner_id: w.owner.owner_id } })).status, 201);
    const key = await w.newKey();
    const enrollment = await w.enroll(handle, key, 1);
    assert.equal(enrollment.en.status, 201);
    assert.equal(enrollment.en.json.status, 'pending');
    const path = `/agents/${encodeURIComponent(handle)}/keys/${key.kid}`;
    expire = () => w.advance(1);
    if (delayed) armed = true;
    else expire();
    const proof = await enrollment.prove();
    assert.equal(proof.status, 401, proof.text);
    assert.equal(proof.json.error, 'key_revoked');
    assert.equal(proof.json.status, undefined);
    assert.equal(proof.json.next, undefined);
    const read = await w.req('GET', path, { headers: w.cred });
    assert.equal(read.status, 200, read.text);
    assert.equal(read.json.status, 'expired');
    const list = await w.req('GET', `/agents/${encodeURIComponent(handle)}/keys`, { headers: w.cred });
    assert.equal(list.json.keys[0].status, 'expired');
    assert.equal((await store.getKey(key.kid, handle))?.status, 'pending', 'reporting expiry does not activate the key');
    const replacement = await w.enroll(handle, key);
    assert.equal(replacement.en.status, 201, 'effective expiry frees this enrollment slot');
    assert.equal((await replacement.prove()).status, 200, 'a fresh authorized enrollment can succeed');
  });
  test(`${backend}: a proof expiring during acceptance keeps its error bound to the original enrollment`, async (t) => {
    const directory = mkdtempSync(join(tmpdir(), 'agentlogin-pending-replacement-'));
    const store = backend === 'memory' ? new MemoryStore() : new SQLiteStore(join(directory, 'issuer.sqlite'));
    t.after(() => { if (store instanceof SQLiteStore) store.close(); rmSync(directory, { recursive: true, force: true }); });
    let replace: (() => Promise<void>) | undefined;
    const wrapped = new Proxy(store, { get(target, property) {
      const value = Reflect.get(target, property, target);
      if (property === 'activateKey') return async (...args: Parameters<Store['activateKey']>) => {
        if (replace) {
          const action = replace; replace = undefined;
          await action();
          args[3] += 1;
        }
        return target.activateKey(...args);
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const w = await world({ store: wrapped });
    const handle = 'replaced-pending@example.com';
    assert.equal((await w.req('POST', '/admin/agents', { headers: w.admin, json: { handle, owner_id: w.owner.owner_id } })).status, 201);
    const key = await w.newKey();
    const original = await w.enroll(handle, key, 1);
    let replacement: Awaited<ReturnType<typeof w.enroll>> | undefined;
    replace = async () => {
      w.advance(1);
      replacement = await w.enroll(handle, key);
      assert.equal(replacement.en.status, 201);
    };
    const proof = await original.prove();
    assert.equal(proof.status, 401, proof.text);
    assert.equal(proof.json.error, 'key_revoked');
    assert.equal((await store.getKey(key.kid, handle))?.status, 'pending');
    assert.equal((await replacement!.prove()).status, 200, 'the stale proof leaves the new enrollment challenge intact');
  });
}
