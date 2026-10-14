import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { decodeJwt } from 'jose';
import { createIssuer, MemoryStore, isAuthenticationTooOld } from '../src/index.js';
import { world } from './fixtures.js';
import { hookable } from './stores.js';

test('max_age accepts decimal integer seconds and rejects malformed or repeated parameters without creating transactions', async () => {
  const w = await world();
  const client = await w.client();
  const { app } = await createIssuer({ issuer: 'https://issuer.test', handleDomains: ['example.com'], store: w.store });
  const params = () => new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uri,
    scope: 'openid', state: 'test-state', nonce: 'test-nonce', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' });
  for (const method of ['GET', 'POST']) {
    for (const value of ['-1', '+1', '1.5', '1e3', ' 1', '1 ', 'NaN', 'Infinity', '0x10', '1\n']) {
      const query = params(); query.set('max_age', value);
      const response = await app.request(`https://issuer.test/authorize${method === 'GET' ? `?${query}` : ''}`, {
        method, headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
        ...(method === 'POST' ? { body: query.toString() } : {}),
      });
      const body = await response.json() as any;
      assert.equal(response.status, 400, `${method} ${JSON.stringify(value)}`);
      assert.equal(body.error, 'invalid_request');
      assert.equal(new URL(body.redirect).searchParams.get('state'), 'test-state');
      assert.equal(new URL(body.redirect).searchParams.get('iss'), 'https://issuer.test');
    }
    const duplicate = params(); duplicate.append('max_age', '0'); duplicate.append('max_age', '0');
    const response = await app.request(`https://issuer.test/authorize${method === 'GET' ? `?${duplicate}` : ''}`, {
      method, headers: { accept: 'text/html', 'content-type': 'application/x-www-form-urlencoded' },
      ...(method === 'POST' ? { body: duplicate.toString() } : {}),
    });
    assert.equal(response.status, 303);
    const redirect = new URL(response.headers.get('location')!);
    assert.equal(redirect.searchParams.get('error'), 'invalid_request');
    assert.equal(redirect.searchParams.get('state'), 'test-state');
  }
  assert.equal((await w.store.listOpenTransactions({})).length, 0);
  for (const method of ['GET', 'POST']) {
    const query = params(); query.set('max_age', '');
    const response = await app.request(`https://issuer.test/authorize${method === 'GET' ? `?${query}` : ''}`, {
      method, headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
      ...(method === 'POST' ? { body: query.toString() } : {}),
    });
    assert.equal(response.status, 200, `${method}: empty optional max_age is omitted`);
    const body = await response.json() as any;
    assert.equal((await w.store.getTransaction(body.transaction_id))?.maxAge, undefined, 'empty is not max_age=0');
  }
  for (const [wire, stored] of [['0', 0], ['00001', 1], ['10', 10], ['9'.repeat(400), Number.MAX_SAFE_INTEGER]] as const) {
    const started = await w.start(client, { max_age: wire });
    assert.equal((await w.store.getTransaction(started.tx.transaction_id))?.maxAge, stored);
  }
});

test('authentication age helper allows equality and zero delay, fails closed for missing authentication', () => {
  assert.equal(isAuthenticationTooOld(10, 100, 110), false);
  assert.equal(isAuthenticationTooOld(10, 100, 111), true);
  assert.equal(isAuthenticationTooOld(0, 100, 1000), false);
  assert.equal(isAuthenticationTooOld(undefined, undefined, 1000), false);
  for (const age of [0, 10]) assert.equal(isAuthenticationTooOld(age, undefined, 1000), true);
});

for (const maxAge of [0, 10]) {
  test(`delayed Owner approval preserves auth_time with max_age=${maxAge}`, async () => {
    const w = await world();
    const agent = await w.agent('freshness@example.com');
    const client = await w.client({ max_signups_per_owner: 1 });
    const started = await w.start(client, { scope: 'openid owner_profile', max_age: String(maxAge) });
    const accepted = await w.assertOn(started.tx, agent);
    assert.equal(accepted.json.status, 'awaiting_owner');
    const original = (await w.store.getTransaction(started.tx.transaction_id))!;
    w.advance(11);
    const approval = await w.req('POST', `/owner/transactions/${started.tx.transaction_id}/decision`, { headers: w.cred, json: { decision: 'approve' } });
    assert.equal(approval.json.status, 'ready', approval.text);
    assert.equal((await w.store.getTransaction(original.id))?.assertedAt, original.assertedAt);
    const polled = await w.req('GET', started.tx.url, { headers: { authorization: `Bearer ${accepted.json.transaction_token}` } });
    const continued = await w.cont({ ...polled.json, transaction_token: accepted.json.transaction_token });
    const redirect = new URL(continued.json.redirect);
    if (maxAge > 0) {
      assert.equal(redirect.searchParams.get('error'), 'login_required');
      assert.equal(redirect.searchParams.get('code'), null);
      const denied = (await w.store.getTransaction(original.id))!;
      assert.equal(denied.status, 'denied');
      assert.equal(denied.reason, 'login_required');
      assert.equal(denied.assertedAt, original.assertedAt);
      assert.equal(denied.expiresAt, original.expiresAt);
      assert.equal(denied.codeIssued, false);
      assert.equal(await w.store.getAccount(agent.handle, client.client_id), undefined);
      assert.equal(await w.store.signupsEver(w.owner.owner_id, client.client_id), 0);
    } else {
      w.advance(2);
      const token = await w.token(client, redirect.searchParams.get('code')!, started.verifier);
      assert.equal(token.status, 200, token.text);
      assert.equal(decodeJwt(token.json.id_token).auth_time, original.assertedAt);
      assert.equal((await w.userinfo(token.json.access_token)).status, 200);
    }
  });
}

for (const phase of ['redemption', 'issuance', 'delivery'] as const) {
  test(`positive max_age rejects a code that ages before ${phase}`, async () => {
    const hooks = hookable(new MemoryStore());
    const w = await world({ store: hooks.store });
    const agent = await w.agent('aging@example.com');
    const client = await w.client();
    const started = await w.start(client, { max_age: '1' });
    const accepted = await w.assertOn(started.tx, agent);
    const continued = await w.cont(accepted.json);
    const code = new URL(continued.json.redirect).searchParams.get('code')!;
    let issuedHash: string | undefined;
    if (phase === 'redemption') w.advance(2);
    else hooks.after(phase === 'issuance' ? 'redeemCode' : 'getAccessToken', async () => {
      const snapshot = (await w.store.getCode(createHash('sha256').update(code).digest('base64url')))!;
      assert.equal(snapshot.used, true);
      w.advance(2);
    });
    if (phase === 'delivery') {
      // Retain only the hash to prove that the undisclosed token was revoked before the error response.
      const insert = w.store.insertAccessToken.bind(w.store);
      w.store.insertAccessToken = async (token, now) => { issuedHash = token.hash; return insert(token, now); };
    }
    const rejected = await w.token(client, code, started.verifier);
    assert.equal(rejected.status, 400, rejected.text);
    assert.equal(rejected.json.error, 'invalid_grant');
    assert.equal(rejected.json.access_token, undefined);
    assert.equal(rejected.json.id_token, undefined);
    if (issuedHash) assert.equal((await w.store.getAccessToken(issuedHash))?.revoked, true);
  });
}

test('max_age bounds authentication, not a successfully issued Access Token lifetime', async () => {
  const w = await world();
  const agent = await w.agent('session@example.com');
  const client = await w.client();
  const started = await w.start(client, { max_age: '1' });
  const accepted = await w.assertOn(started.tx, agent);
  const continued = await w.cont(accepted.json);
  const token = await w.token(client, new URL(continued.json.redirect).searchParams.get('code')!, started.verifier);
  assert.equal(token.status, 200, token.text);
  w.advance(2);
  assert.equal((await w.userinfo(token.json.access_token)).status, 200);
});
