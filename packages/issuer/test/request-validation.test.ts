import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createIssuer } from '../src/index.js';
import { world } from './fixtures.js';

test('registration requires an explicit supported authentication method', async () => {
  const w = await world();
  for (const method of [undefined, null, '', 'none', 'unsupported']) {
    const response = await w.req('POST', '/register', {
      headers: w.admin,
      json: { redirect_uris: ['https://rp.example/cb'], token_endpoint_auth_method: method },
    });
    assert.equal(response.status, 400, `method ${String(method)}`);
    assert.equal(response.json.error, 'invalid_client_metadata');
    assert.equal(response.json.client_id, undefined);
    assert.equal(response.json.client_secret, undefined);
  }
  for (const method of ['client_secret_basic', 'client_secret_post']) {
    const response = await w.req('POST', '/register', {
      headers: w.admin,
      json: { redirect_uris: ['https://rp.example/cb'], token_endpoint_auth_method: method },
    });
    assert.equal(response.status, 201);
    assert.equal(response.json.token_endpoint_auth_method, method);
    assert.equal((await w.store.getClient(response.json.client_id))?.tokenEndpointAuthMethod, method);
  }
});

test('repeated unknown authorization parameters fail in query, body and both without creating transactions', async () => {
  const w = await world();
  const client = await w.client();
  const { app } = await createIssuer({ issuer: 'https://issuer.test', handleDomains: ['example.com'], store: w.store });
  const params = () => new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uri,
    scope: 'openid', state: 'validation-state', nonce: 'validation-nonce', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' });
  for (const source of ['query', 'body', 'query-and-body'] as const) {
    for (const accept of ['application/json', 'text/html']) {
      const query = source === 'query' ? params() : new URLSearchParams();
      const body = source === 'query' ? undefined : params();
      const destination = source === 'query' ? query : body!;
      destination.append('x-extension', 'first');
      (source === 'query-and-body' ? query : destination).append('x-extension', 'second');
      const response = await app.request(`https://issuer.test/authorize?${query}`, {
        method: body ? 'POST' : 'GET',
        headers: { accept, 'content-type': 'application/x-www-form-urlencoded' },
        body: body?.toString(),
      });
      assert.equal(response.status, accept === 'text/html' ? 303 : 400, `${source}, ${accept}`);
      const json = accept === 'application/json' ? await response.json() as Record<string, string> : undefined;
      if (json) {
        assert.equal(json.error, 'invalid_request');
        assert.equal(json.transaction_id, undefined);
      }
      const redirect = new URL(json?.redirect ?? response.headers.get('location')!);
      assert.equal(redirect.origin + redirect.pathname, client.redirect_uri);
      assert.equal(redirect.searchParams.get('error'), 'invalid_request');
      assert.equal(redirect.searchParams.get('state'), 'validation-state');
      assert.equal(redirect.searchParams.get('iss'), 'https://issuer.test');
    }
  }
  assert.equal((await w.store.listOpenTransactions({})).length, 0);

  const invalidTarget = params();
  invalidTarget.set('redirect_uri', 'https://unregistered.example/cb');
  invalidTarget.append('x-extension', 'first');
  invalidTarget.append('x-extension', 'second');
  const rejected = await app.request(`https://issuer.test/authorize?${invalidTarget}`, { headers: { accept: 'application/json' } });
  assert.equal(rejected.status, 400);
  assert.equal((await rejected.json() as Record<string, unknown>).redirect, undefined);
  assert.equal((await w.store.listOpenTransactions({})).length, 0);

  const unique = params(); unique.set('x-extension', 'ignored');
  assert.equal((await app.request(`https://issuer.test/authorize?${unique}`, { headers: { accept: 'application/json' } })).status, 200,
    'a single unknown extension is still ignored');
});
