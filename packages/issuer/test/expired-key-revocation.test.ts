import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONSTANTS, MemoryStore } from '../src/index.js';
import { SQLiteStore } from '../src/sqlite-store.js';
import { world } from './fixtures.js';
import { snapshotting } from './stores.js';

async function setup(t: TestContext, backend: 'memory' | 'sqlite') {
  if (backend === 'memory') return world({ store: snapshotting(new MemoryStore()) });
  const dir = mkdtempSync(join(tmpdir(), 'agentlogin-expired-revocation-'));
  const store = new SQLiteStore(join(dir, 'issuer.sqlite'));
  t.after(() => { store.close(); rmSync(dir, { recursive: true, force: true }); });
  return world({ store });
}

for (const backend of ['memory', 'sqlite'] as const) {
  test(`${backend}: individually revoking a retired expired enrollment tombstones only its Agent and preserves retention`, async (t) => {
    const w = await setup(t, backend);
    const a = await w.agent('expired-a@example.com', 1);
    const originalKey = (await w.store.getKey(a.kid, a.handle))!;
    const client = await w.client();
    const original = await w.ready(client, a);
    const readOriginal = () => w.req('GET', original.tx.url);
    const b = { ...a, handle: 'expired-b@example.com' };
    assert.equal((await w.req('POST', '/admin/agents', {
      headers: w.admin, json: { handle: b.handle, owner_id: w.owner.owner_id },
    })).status, 201);

    w.advance(1);
    const enrollment = await w.enroll(b.handle, b, 10);
    assert.equal(enrollment.en.status, 201, enrollment.en.text);
    assert.equal((await enrollment.prove()).status, 200);
    assert.equal((await w.store.getKey(a.kid, a.handle))?.status, 'expired', 'B activation retires A in storage');
    const bEnrollment = (await w.store.getKey(b.kid, b.handle))!.enrollment;
    const issued = await w.codeFor(client, b);
    const token = await w.token(client, issued.code, issued.verifier);
    assert.equal(token.status, 200, token.text);
    const pending = await w.ready(client, b);

    // Revoke after the original terminal time so a restarted retention period is observable.
    w.advance(2);
    const revoked = await w.revoke(a);
    assert.equal(revoked.status, 204, revoked.text);
    const revokedKey = (await w.store.getKey(a.kid, a.handle))!;
    assert.equal(revokedKey.status, 'revoked', 'DELETE must persist revocation of a stored-expired enrollment');
    assert.equal(revokedKey.enrollment, originalKey.enrollment);
    assert.equal(revokedKey.revokedAt, originalKey.expiresAt + 2);
    assert.equal(await w.store.wasRevoked(a.handle, a.kid), true);
    const managed = await w.req('GET', `/agents/${encodeURIComponent(a.handle)}/keys/${a.kid}`, { headers: w.cred });
    assert.equal(managed.status, 200, managed.text);
    assert.equal(managed.json.status, 'revoked');

    const preserved = (await w.store.getKey(b.kid, b.handle))!;
    assert.equal(preserved.status, 'active');
    assert.equal(preserved.enrollment, bEnrollment);
    assert.equal(await w.store.wasRevoked(b.handle, b.kid), false);
    assert.equal((await w.userinfo(token.json.access_token)).status, 200, 'B tokens survive revocation of A');
    assert.equal((await w.store.getTransaction(pending.tx.transaction_id))?.status, 'ready');
    const continued = await w.cont(pending.tx);
    assert.equal(continued.status, 200, continued.text);
    const code = new URL(continued.json.redirect).searchParams.get('code');
    assert.ok(code, 'B can finish its existing sign-in after A is revoked');
    assert.equal((await w.token(client, code, pending.verifier)).status, 200);

    const terminal = (await w.store.getTransaction(original.tx.transaction_id))!;
    assert.equal(terminal.status, 'denied');
    assert.equal(terminal.reason, 'key_revoked');
    assert.equal(terminal.terminalAt, originalKey.expiresAt, 'individual revocation preserves the original key expiry');
    assert.equal((await w.req('GET', original.tx.url, { headers: { authorization: `Bearer ${original.tx.transaction_token}` } })).status, 401);
    assert.equal((await readOriginal()).status, 200);

    w.advance(8); // B has now expired too: its exclusivity cannot explain rejecting A's enrollment.
    const reenrollment = await w.enroll(a.handle, a);
    assert.equal(reenrollment.en.status, 400, reenrollment.en.text);
    assert.equal(reenrollment.en.json.error, 'invalid_request');
    assert.equal((await w.store.getKey(a.kid, a.handle))?.status, 'revoked');

    w.advance(DEFAULT_CONSTANTS.T_RETAIN - 10);
    assert.equal((await readOriginal()).status, 200, 'the original retention boundary remains readable');
    w.advance(1);
    const hidden = await readOriginal();
    assert.equal(hidden.status, 404, 'revoking the expired enrollment must not restart retention');
    assert.equal(hidden.json.error, 'invalid_transaction');
  });

  test(`${backend}: individually revoking a time-expired active enrollment prevents reenrollment`, async (t) => {
    const w = await setup(t, backend);
    const agent = await w.agent('expired-active@example.com', 1);
    w.advance(3);
    assert.equal((await w.store.getKey(agent.kid, agent.handle))?.status, 'active', 'expiry has not been materialized');
    assert.equal((await w.revoke(agent)).status, 204);
    assert.equal((await w.store.getKey(agent.kid, agent.handle))?.status, 'revoked');
    assert.equal(await w.store.wasRevoked(agent.handle, agent.kid), true);
    const reenrollment = await w.enroll(agent.handle, agent);
    assert.equal(reenrollment.en.status, 400, reenrollment.en.text);
    assert.equal(reenrollment.en.json.error, 'invalid_request');
  });
}
