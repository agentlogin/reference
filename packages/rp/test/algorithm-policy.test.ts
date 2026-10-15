import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RelyingParty, type RelyingPartyOptions } from '../src/index.js';

test('runtime configuration cannot enable legacy or unimplemented signing algorithms', () => {
  const options = { clientId: 'https://app.example/client.json', redirectUri: 'https://app.example/callback', issuers: ['https://issuer.example'], stateSecret: 'test-configuration-secret'.repeat(2) };
  assert.doesNotThrow(() => new RelyingParty(options));
  for (const algs of [[], ['EdDSA'], ['Ed25519'], ['HS256'], ['ES256', 'HS256'], ['none']]) {
    assert.throws(() => new RelyingParty({ ...options, idTokenAlgs: algs as RelyingPartyOptions['idTokenAlgs'] }), /ES256 only/);
  }
});
