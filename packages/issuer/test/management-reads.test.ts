import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { MemoryStore } from '../src/index.js';
import { world } from './fixtures.js';
import { hookable, snapshotting } from './stores.js';

test('a stale account-list request cannot read a replacement Agent accounts', async () => {
  for (const transferOwner of [true, false]) {
    const h = hookable(snapshotting(new MemoryStore()));
    const w = await world({ store: h.store });
    const handle = 'scout@example.com';
    await w.agent(handle);
    const nextOwner = transferOwner
      ? (await w.req('POST', '/admin/owners', { headers: w.admin, json: { email: 'next-owner@example.org', name: 'Next Owner' } })).json
      : w.owner;
    let replacementClientId = '';
    h.after('getAgent', async () => {
      assert.equal((await w.req('DELETE', `/admin/agents/${encodeURIComponent(handle)}`, { headers: w.admin })).status, 204);
      assert.equal((await w.req('POST', '/admin/agents', { headers: w.admin, json: { handle, owner_id: nextOwner.owner_id } })).status, 201);
      const key = await w.newKey();
      const enrollment = await w.req('POST', `/agents/${encodeURIComponent(handle)}/keys`, {
        headers: { authorization: `Bearer ${nextOwner.credential}` }, json: { jwk: key.jwk },
      });
      assert.equal(enrollment.status, 201);
      const proof = await new SignJWT({ nonce: enrollment.json.challenge, jti: randomBytes(16).toString('base64url') })
        .setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid })
        .setIssuer(handle).setSubject(handle).setAudience('https://issuer.test')
        .setIssuedAt(enrollment.json.created_at).setExpirationTime(enrollment.json.created_at + 60).sign(key.privateKey);
      assert.equal((await w.req('POST', enrollment.json.proof_url, { json: { proof } })).status, 200);
      const client = await w.client();
      replacementClientId = client.client_id;
      await w.codeFor(client, { handle, ...key });
    });
    const stale = await w.req('GET', `/agents/${encodeURIComponent(handle)}/accounts`, { headers: w.cred });
    assert.equal(stale.status, 404, 'authorization must remain bound to the original immutable Agent');
    assert.ok(replacementClientId);
    assert.equal(stale.text.includes(replacementClientId), false);
    const fresh = await w.req('GET', `/agents/${encodeURIComponent(handle)}/accounts`, { headers: { authorization: `Bearer ${nextOwner.credential}` } });
    assert.equal(fresh.status, 200);
    assert.equal(fresh.json.accounts[0].client_id, replacementClientId);
  }
});
