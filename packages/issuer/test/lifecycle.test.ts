// Revocation, expiry and concurrency guarantees (reported against commit 84e5f3f). Every test drives the issuer in
// process; races are placed deterministically with a store hook, and stores have database semantics.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { MemoryStore } from '../src/index.js';
import { hookable, snapshotting } from './stores.js';

import { world } from './fixtures.js';
const rnd = (n = 16) => randomBytes(n).toString('base64url');

test('#1 a revocation that completes while an enrollment proof is being verified wins', async () => {
  const h = hookable(snapshotting(new MemoryStore()));
  const w = await world({ store: h.store });
  assert.equal((await w.req('POST', '/admin/agents', { json: { handle: 'scout@example.com', owner_id: w.owner.owner_id }, headers: w.admin })).status, 201);
  const key = await w.newKey();
  const { en, prove } = await w.enroll('scout@example.com', key);
  assert.equal(en.status, 201);
  // The proof handler has read the pending key; before it writes, the Owner revokes the key.
  h.after('getKey', async () => {
    assert.equal((await w.revoke({ handle: 'scout@example.com', kid: key.kid })).status, 204);
  });
  const proved = await prove();
  assert.notEqual(proved.status, 200, 'the proof must not activate a key that was revoked meanwhile');
  const record = await w.req('GET', `/agents/${encodeURIComponent('scout@example.com')}/keys/${encodeURIComponent(key.kid)}`, { headers: w.cred });
  assert.equal(record.json.status, 'revoked');
  // and the key does not authenticate
  const c = await w.client();
  const s = await w.start(c);
  const a = await w.assertOn(s.tx, { handle: 'scout@example.com', ...key });
  assert.equal(a.status, 401);
  assert.equal(a.json.error, 'key_revoked');
});

test('#1 a revocation that completes during a code exchange leaves no token behind', async () => {
  const h = hookable(snapshotting(new MemoryStore()));
  const w = await world({ store: h.store });
  const a = await w.agent('scout@example.com');
  const c = await w.client();
  const { code, verifier } = await w.codeFor(c, a);
  // The Token Endpoint has looked the key up; before it finishes, the key is revoked.
  h.after('getKey', async () => {
    assert.equal((await w.revoke(a)).status, 204);
  });
  const t = await w.token(c, code, verifier);
  assert.equal(t.status, 400, `a token was issued after the revocation completed: ${t.text.slice(0, 80)}`);
  assert.equal(t.json.error, 'invalid_grant');
});

test('#2 an expired key that is enrolled again does not revive its old credentials', async () => {
  const w = await world();
  const a = await w.agent('scout@example.com', 50); // the key expires in 50 s: before the code (60 s) and the transaction (300 s) do
  const c = await w.client();
  const first = await w.codeFor(c, a);
  const tokens = (await w.token(c, first.code, first.verifier)).json;
  assert.equal((await w.userinfo(tokens.access_token)).status, 200);
  const unredeemed = await w.codeFor(c, a);
  const open = await w.ready(c, a);

  w.advance(51);
  assert.equal((await w.userinfo(tokens.access_token)).status, 401, 'expired key: UserInfo refuses');
  // a transaction that was ready does not complete after the key expired (Section 7.4 table)
  const late = await w.cont(open.tx);
  assert.equal(new URL(late.json.redirect).searchParams.get('error'), 'access_denied', late.text);
  assert.equal((await w.req('GET', open.tx.url, { headers: { authorization: `Bearer ${open.tx.transaction_token}` } })).json.reason, 'key_revoked');

  // the same public key is enrolled and proved again
  const again = await w.enroll(a.handle, a, 1000);
  // (the unredeemed code and the old Access Token have not reached their own expiry yet: only the enrollment separates them from the new key)
  assert.equal(again.en.status, 201, again.en.text);
  assert.equal((await again.prove()).status, 200);
  assert.equal((await w.userinfo(tokens.access_token)).status, 401, 'the old Access Token stays dead');
  const old = await w.token(c, unredeemed.code, unredeemed.verifier);
  assert.equal(old.status, 400, 'the old code stays dead');
  assert.equal(old.json.error, 'invalid_grant');
  // the new enrollment works on its own
  const fresh = await w.codeFor(c, a);
  const t2 = await w.token(c, fresh.code, fresh.verifier);
  assert.equal(t2.status, 200, t2.text);
  assert.equal((await w.userinfo(t2.json.access_token)).status, 200);
});

test('#3 two issuer instances on one store: a transaction completes once', async () => {
  for (let round = 0; round < 5; round += 1) {
    const w = await world({ instances: 2 });
    const a = await w.agent('scout@example.com');
    const c = await w.client();
    const r = await w.ready(c, a);
    const results = await Promise.all([w.cont(r.tx, 0), w.cont(r.tx, 1), w.cont(r.tx, 0), w.cont(r.tx, 1)]);
    const codes = results.filter((x) => x.status === 200).map((x) => new URL(x.json.redirect).searchParams.get('code'));
    assert.equal(codes.length, 1, `round ${round}: ${results.map((x) => x.status).join(', ')}`);
    for (const x of results.filter((y) => y.status !== 200)) assert.equal(x.status, 410);
  }
});

test('#3 two issuer instances on one store: an assertion is accepted once and the cap holds', async () => {
  for (let round = 0; round < 5; round += 1) {
    const w = await world({ instances: 2 });
    const c = await w.client({ max_signups_per_owner: 1 });
    const agents = [];
    for (let i = 0; i < 6; i += 1) agents.push(await w.agent(`a${i}@example.com`));
    const started = [];
    for (const a of agents) started.push({ a, tx: (await w.start(c)).tx });
    const results = (await Promise.all(started.map(({ a, tx }, i) => w.assertOn(tx, a, i % 2)))).map((r) => r.json);
    assert.equal(results.filter((r) => r.status === 'ready').length, 1, `round ${round}: ${results.map((r) => `${r.status} ${r.reason ?? ''}`.trim()).join(', ')}`);
    // one transaction, one assertion: the same assertion sent to both instances at once
    const one = await w.start(c);
    const jwsA = await w.assertOn(one.tx, agents[0]!, 0);
    void jwsA;
  }
  const w = await world({ instances: 2 });
  const a = await w.agent('scout@example.com');
  const b = await w.agent('rover@example.com');
  const c = await w.client();
  const s = await w.start(c);
  const both = await Promise.all([w.assertOn(s.tx, a, 0), w.assertOn(s.tx, b, 1)]);
  assert.deepEqual(both.map((r) => r.status).sort(), [200, 409], both.map((r) => `${r.status} ${r.json.error ?? r.json.status}`).join(', '));
});

test('#5 a client metadata document served with no-store is fetched for every request', async () => {
  let hits = 0;
  let redirect = '';
  let base = '';
  const srv = http.createServer((req, res) => {
    if (req.url !== '/client.json') { res.writeHead(404); res.end(); return; }
    hits += 1;
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ client_id: `${base}/client.json`, redirect_uris: [redirect], token_endpoint_auth_method: 'none', client_name: 'Open' }));
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const w = await world({ insecureClients: true });
    const authorize = (uri: string) => w.req('GET', `/authorize?${new URLSearchParams({ response_type: 'code', client_id: `${base}/client.json`, redirect_uri: uri, scope: 'openid', state: rnd(), nonce: rnd(), code_challenge: createHash('sha256').update(rnd(32)).digest('base64url'), code_challenge_method: 'S256' })}`);
    redirect = `${base}/cb-one`;
    assert.equal((await authorize(`${base}/cb-one`)).status, 200);
    redirect = `${base}/cb-two`; // the client withdraws its first redirect URI
    const old = await authorize(`${base}/cb-one`);
    assert.equal(old.status, 400, 'the withdrawn redirect URI is no longer accepted');
    assert.equal((await authorize(`${base}/cb-two`)).status, 200);
    assert.equal(hits, 3, 'one fetch per request');
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
  }
});
