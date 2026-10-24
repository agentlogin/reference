import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { probe } from './monitor.mjs';

const application = 'https://workspace.example', issuer = 'https://issuer.example';
const metadata = { issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', userinfo_endpoint: issuer + '/userinfo', jwks_uri: issuer + '/jwks', response_types_supported: ['code'], code_challenge_methods_supported: ['S256'], id_token_signing_alg_values_supported: ['ES256'] };
const jwk = { ...generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }), kid: 'key-one', use: 'sig', alg: 'ES256' };
function fake(overrides = {}) {
  return async (url, init) => {
    assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    const bodies = {
      [application + '/healthz']: { status: 'alive' },
      [application + '/readyz']: { status: 'ready' },
      [application + '/client-metadata.json']: { client_id: application + '/client-metadata.json', redirect_uris: [application + '/auth/agent/callback'], initiate_login_uri: application + '/auth/agent/login', client_name: 'Agent Workspace' },
      [application + '/me']: { error: 'not signed in' },
      [issuer + '/.well-known/openid-configuration']: metadata,
      [issuer + '/jwks']: { keys: [jwk] },
      ...overrides,
    };
    assert.ok(Object.hasOwn(bodies, url), 'probe followed an unexpected origin or path');
    return Response.json(bodies[url], { status: url.endsWith('/me') ? 401 : 200, headers: { 'cache-control': 'no-store' } });
  };
}
test('public probe checks bindings and discloses its unauthenticated scope', async () => {
  const result = await probe({ application, issuer }, fake());
  assert.equal(result.passed, true);
  assert.equal(result.authenticatedSignIn, false);
  assert.equal(result.alertDeliveryVerified, false);
});
for (const [name, override] of Object.entries({
  'wrong issuer': { [issuer + '/.well-known/openid-configuration']: { ...metadata, issuer: 'https://other.example' } },
  'foreign key endpoint': { [issuer + '/.well-known/openid-configuration']: { ...metadata, jwks_uri: 'https://other.example/jwks' } },
  'missing PKCE': { [issuer + '/.well-known/openid-configuration']: { ...metadata, code_challenge_methods_supported: [] } },
  'empty keys': { [issuer + '/jwks']: { keys: [] } },
  'private key': { [issuer + '/jwks']: { keys: [{ ...jwk, d: 'private-material' }] } },
  'duplicate keys': { [issuer + '/jwks']: { keys: [jwk, jwk] } },
  'malformed coordinates': { [issuer + '/jwks']: { keys: [{ ...jwk, x: 'missing' }] } },
  'algorithm mismatch': { [issuer + '/jwks']: { keys: [{ ...jwk, crv: 'P-384' }] } },
})) test(`public probe rejects ${name}`, async () => { await assert.rejects(probe({ application, issuer }, fake(override))); });
