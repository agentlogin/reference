#!/usr/bin/env node
// One credential-free public probe. An external scheduler owns alert delivery and confirmation.
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { origin, readJson, smoke } from '../acceptance.mjs';

export async function probe({ application, issuer }, request = fetch) {
  const app = origin(application), id = origin(issuer);
  const started = performance.now();
  await smoke(app, request);
  const get = (path) => request(id + path, { redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } });
  const metadata = await readJson(await get('/.well-known/openid-configuration'), 200);
  assert.equal(metadata.issuer, id);
  for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) {
    const url = new URL(metadata[key]);
    assert.equal(url.origin, id);
    assert.equal(url.username + url.password + url.search + url.hash, '');
  }
  assert.ok(metadata.response_types_supported?.includes('code'));
  assert.ok(metadata.code_challenge_methods_supported?.includes('S256'));
  assert.ok(metadata.id_token_signing_alg_values_supported?.includes('ES256'));
  const keys = await readJson(await request(metadata.jwks_uri, { redirect: 'error', signal: AbortSignal.timeout(10_000) }), 200);
  assert.ok(Array.isArray(keys.keys) && keys.keys.length > 0 && keys.keys.length <= 100);
  const ids = new Set();
  for (const key of keys.keys) {
    assert.ok(typeof key.kid === 'string' && key.kid.length > 0 && key.kid.length <= 1024);
    assert.equal(ids.has(key.kid), false);
    ids.add(key.kid);
    assert.equal(key.use, 'sig');
    assert.ok(['ES256', 'Ed25519'].includes(key.alg));
    assert.equal(Object.hasOwn(key, 'd'), false);
    assert.equal(Object.hasOwn(key, 'k'), false);
    assert.ok(key.alg === 'ES256' ? key.kty === 'EC' && key.crv === 'P-256' : key.kty === 'OKP' && key.crv === 'Ed25519');
    for (const field of key.alg === 'ES256' ? ['x', 'y'] : ['x']) {
      assert.equal(typeof key[field], 'string');
      assert.equal(Buffer.from(key[field], 'base64url').length, 32);
      assert.equal(Buffer.from(key[field], 'base64url').toString('base64url'), key[field]);
    }
    createPublicKey({ key, format: 'jwk' });
  }
  return { passed: true, checkedAt: new Date().toISOString(), durationMs: Math.round(performance.now() - started), publicApplication: true, issuerMetadata: true, publicSigningKeys: true, authenticatedSignIn: false, alertDeliveryVerified: false };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    console.log(JSON.stringify(await probe({ application: process.env.PILOT_BASE_URL, issuer: process.env.PILOT_ISSUER })));
  } catch {
    // No raw request/response, tokens, cookies, private claims or driver error values enter alert text.
    console.log(JSON.stringify({ passed: false, checkedAt: new Date().toISOString(), error: 'public_probe_failed', alertDeliveryVerified: false }));
    process.exitCode = 1;
  }
}
