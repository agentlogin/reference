import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { runConformance } from '../src/index.js';
import { concurrentAccessTokens, redirectMatches, validateMetadata, validateForbiddenMetadata } from '../src/validation.js';

const issuer = 'https://issuer.example';
const metadata = (base = issuer): Record<string, unknown> => ({
  issuer: base,
  authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, userinfo_endpoint: `${base}/userinfo`,
  jwks_uri: `${base}/jwks`, transaction_endpoint: `${base}/transactions`, agents_endpoint: `${base}/agents`, registration_endpoint: `${base}/register`,
  response_types_supported: ['code'], response_modes_supported: ['query'], grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'], id_token_signing_alg_values_supported: ['ES256'], agent_key_algs_supported: ['ES256'],
  token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'], subject_types_supported: ['public'],
  client_id_metadata_document_supported: true, authorization_response_iss_parameter_supported: true,
  request_parameter_supported: false, request_uri_parameter_supported: false,
  scopes_supported: ['openid', 'email', 'profile', 'owner_profile', 'owner_email'], handle_domains: ['example.com'],
  agent_login_versions_supported: ['1.0'],
});

test('metadata checks reject missing members, wrong types, unsafe endpoints and omitted conditional requirements', () => {
  validateMetadata(metadata(), issuer, true);
  for (const [name, value] of [
    ['response_modes_supported', undefined], ['response_modes_supported', ['query', 'fragment']],
    ['subject_types_supported', ['pairwise']], ['subject_types_supported', undefined],
    ['response_types_supported', 'code'], ['scopes_supported', 'openid email profile owner_profile owner_email'],
    ['code_challenge_methods_supported', 'S256'], ['id_token_signing_alg_values_supported', 'ES256'],
    ['agent_key_algs_supported', 'ES256'], ['agent_login_versions_supported', '1.0'],
    ['handle_domains', 'example.com'], ['handle_domains', ['EXAMPLE.com']], ['handle_domains', ['*.']],
    ['handle_domains', ['exam_ple.com']], ['handle_domains', ['éxample.com']], ['handle_domains', ['127.0.0.1']],
    ['handle_domains', [null]], ['token_endpoint_auth_methods_supported', 'none client_secret_basic'],
    ['request_parameter_supported', true], ['request_uri_parameter_supported', undefined],
    ['authorization_endpoint', null], ['token_endpoint', '/token'], ['agents_endpoint', 'http://remote.example/agents'],
    ['userinfo_endpoint', 'https://issuer.example/userinfo#fragment'], ['jwks_uri', 'https://user:password@issuer.example/jwks'],
    ['registration_endpoint', undefined], ['home_issuers', ['*', 'https://home.example']], ['home_issuers', ['https://home.example']],
  ] as Array<[string, unknown]>) {
    assert.throws(() => validateMetadata({ ...metadata(), [name]: value }, issuer, true), undefined, `${name}=${JSON.stringify(value)}`);
  }
  assert.throws(() => validateMetadata({ ...metadata(), token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'private_key_jwt'] }, issuer, true), /token_endpoint_auth_signing_alg_values_supported/);
  assert.throws(() => validateMetadata({ ...metadata(), token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['RS256'] }, issuer, true), /ES256/);
  validateMetadata({ ...metadata(), response_types_supported: ['code', 'extension'], handle_domains: [], home_issuers: ['*'], op_policy_uri: 'https://relay.example/policy' }, issuer, false);
  validateMetadata({ ...metadata(), handle_domains: ['*.xn--bcher-kva.example'] }, issuer, false);
});

test('prohibited algorithms and PKCE modes cannot pass I-2', () => {
  validateForbiddenMetadata(metadata());
  for (const bad of [
    { end_session_endpoint: 'https://issuer.example/logout' },
    { grant_types_supported: ['authorization_code', 'refresh_token'] },
    { code_challenge_methods_supported: ['S256', 'plain'] },
    { id_token_signing_alg_values_supported: ['ES256', 'RS256'] },
    { id_token_signing_alg_values_supported: ['ES256', 'none'] },
    { agent_key_algs_supported: ['ES256', 'none'] },
    { token_endpoint_auth_signing_alg_values_supported: ['ES256', 'none'] },
  ]) assert.throws(() => validateForbiddenMetadata({ ...metadata(), ...bad }));
});

test('HTTP development exception is confined to the configured loopback origin', () => {
  const local = 'http://127.0.0.1:4321';
  validateMetadata(metadata(local), local, true);
  assert.throws(() => validateMetadata({ ...metadata(local), agents_endpoint: 'http://127.0.0.1:4322/agents' }, local, true), /agents_endpoint/);
  assert.throws(() => validateMetadata({ ...metadata(), agents_endpoint: `${local}/agents` }, issuer, true), /agents_endpoint/);
  assert.throws(() => validateMetadata(metadata('http://remote.example'), 'http://remote.example', true), /issuer/);
});

test('invalid discovery reports failure before any credential-bearing bootstrap request', async () => {
  const seen: Array<{ url?: string; authorization?: string }> = [];
  let base = '';
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, authorization: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ...metadata(base), response_modes_supported: ['fragment'] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const report = await runConformance({ issuer: base, adminToken: 'do-not-send' });
    assert.equal(report.results.find((r) => r.id === 'I-1')?.outcome, 'fail');
    assert.match(report.results.find((r) => r.id === 'I-1')?.detail ?? '', /response_modes_supported/);
    assert.deepEqual(seen, [{ url: '/.well-known/openid-configuration', authorization: undefined }]);
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test('callback comparison retains application query parameters and rejects prefix, mutation and duplicate loss', () => {
  const callback = 'https://rp.example/cb?tenant=a%20b&tag=one&tag=two&tag=two&return=%2Fhome';
  const good = new URL(callback);
  good.searchParams.set('code', 'code');
  good.searchParams.set('state', 'state');
  good.searchParams.set('iss', issuer);
  assert.equal(redirectMatches(good, callback), true);
  for (const mutate of [
    (u: URL) => { u.hostname = 'attacker.example'; }, (u: URL) => { u.pathname += '/elsewhere'; },
    (u: URL) => { u.searchParams.set('tenant', 'other'); }, (u: URL) => { u.searchParams.delete('return'); },
    (u: URL) => { u.searchParams.delete('tag'); u.searchParams.append('tag', 'one'); u.searchParams.append('tag', 'two'); },
    (u: URL) => { u.hash = 'fragment'; }, (u: URL) => { u.username = 'other'; },
  ]) {
    const bad = new URL(good);
    mutate(bad);
    assert.equal(redirectMatches(bad, callback), false, bad.href);
  }
});

test('concurrent redemption permits zero or one success, but never two successes or tokens in an error', () => {
  const refused = { status: 400, json: { error: 'invalid_grant' } };
  const issued = { status: 200, json: { access_token: 'access', id_token: 'id' } };
  assert.deepEqual(concurrentAccessTokens([refused, refused, refused]), [], 'replay may invalidate the winning request before it returns tokens');
  assert.deepEqual(concurrentAccessTokens([refused, issued, refused]), ['access']);
  assert.throws(() => concurrentAccessTokens([issued, issued, refused]), /at most one/);
  assert.throws(() => concurrentAccessTokens([issued, { status: 500, json: { error: 'server_error' } }]), /400 invalid_grant/);
  assert.throws(() => concurrentAccessTokens([refused, { status: 400, json: { error: 'invalid_grant', access_token: 'leaked' } }]), /without tokens/);
  assert.throws(() => concurrentAccessTokens([refused, { status: 200, json: { error: 'invalid_grant' } }]), /must return access_token and id_token/);
});
