import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { runConformance } from '../src/index.js';
import { authorizationRedirectMatches, concurrentAccessTokens, redirectMatches, singleUseContinueError, validateMetadata, validateForbiddenMetadata } from '../src/validation.js';

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

test('authorization responses bind unique protocol members while retaining reordered application parameters', () => {
  const callback = 'https://rp.example/cb?tenant=a%20b&tag=one&tag=two&tag=two';
  for (const response of ['code', 'error'] as const) {
    const good = new URL(callback);
    good.searchParams.set('state', 'state');
    good.searchParams.set('iss', issuer);
    good.searchParams.set(response, response === 'code' ? 'the-code' : 'access_denied');
    good.search = new URLSearchParams([...good.searchParams].reverse()).toString();
    const matches = (u: URL) => authorizationRedirectMatches(u, callback, 'state', issuer, response);
    assert.equal(matches(good), true);
    for (const name of ['state', 'iss', response, 'error_description', 'error_uri']) {
      const duplicate = new URL(good);
      if (!duplicate.searchParams.has(name)) duplicate.searchParams.set(name, 'first');
      duplicate.searchParams.append(name, 'conflicting');
      assert.equal(matches(duplicate), false, `duplicate ${name}`);
    }
    for (const name of ['state', 'iss', response]) {
      const missing = new URL(good);
      missing.searchParams.delete(name);
      assert.equal(matches(missing), false, `missing ${name}`);
      missing.searchParams.set(name, '');
      assert.equal(matches(missing), false, `empty ${name}`);
    }
    const mixed = new URL(good);
    mixed.searchParams.set(response === 'code' ? 'error' : 'code', '');
    assert.equal(matches(mixed), false, 'an empty conflicting response member is still mixed');
    const changedApplication = new URL(good);
    changedApplication.searchParams.set('tag', 'one');
    assert.equal(matches(changedApplication), false, 'application query multiplicity is preserved');
  }
});

test('single-use continuation errors retain the terminal status and its required next step', () => {
  const endpoint = 'https://issuer.example/transactions';
  const url = 'https://issuer.example/transactions/txn/continue/secret';
  for (const status of ['denied', 'expired'] as const) {
    const body = { error: 'transaction_expired', status, next: { action: 'continue', method: 'GET', url } };
    assert.equal(singleUseContinueError(body, status, endpoint), true);
    assert.equal(singleUseContinueError({ ...body, next: { ...body.next, url: `${url}-rotated` } }, status, endpoint), true, 'the current continue URL need not equal the previous URL');
    for (const mutation of [
      { status: undefined }, { status: 'completed' }, { status: status === 'denied' ? 'expired' : 'denied' },
      { next: undefined }, { next: [] }, { next: { action: 'none' } },
      { next: { ...body.next, method: 'POST' } }, { next: { ...body.next, method: undefined } },
      { next: { ...body.next, url: undefined } },
      ...['/relative', 'https://attacker.example/continue', `${url}#fragment`, 'https://user:password@issuer.example/continue', 'http://issuer.example/continue'].map((url) => ({ next: { ...body.next, url } })),
    ]) assert.equal(singleUseContinueError({ ...body, ...mutation }, status, endpoint), false, JSON.stringify(mutation));
  }
});

test('completed continuation errors permit well-formed optional next method and URL members', () => {
  const url = 'https://issuer.example/transactions/txn';
  const body = { error: 'transaction_expired', status: 'completed', next: { action: 'none' } };
  for (const optional of [{}, { method: 'GET' }, { method: 'POST' }, { method: 'CUSTOM-METHOD' }, { url }, { method: 'GET', url },
    { url: `${url}#fragment` }, { url: 'https://user:password@issuer.example/transactions/txn' }]) {
    assert.equal(singleUseContinueError({ ...body, next: { ...body.next, ...optional } }, 'completed'), true, JSON.stringify(optional));
  }
  assert.equal(singleUseContinueError({ ...body, next: { ...body.next, url } }, 'completed', 'https://other.example/transactions'), true, 'action none does not require a same-origin URL');
  const local = { ...body, next: { ...body.next, method: 'GET', url: 'http://127.0.0.1:4321/transactions/txn' } };
  assert.equal(singleUseContinueError(local, 'completed', 'http://127.0.0.1:4321/transactions'), true);
  assert.equal(singleUseContinueError(local, 'completed', 'http://127.0.0.1:4322/transactions'), false);
  assert.equal(singleUseContinueError(local, 'completed', 'https://issuer.example/transactions'), false);
  for (const mutation of [
    { error: undefined }, { error: 'invalid_transaction' }, { status: undefined }, { status: 'denied' }, { status: 'expired' },
    { next: undefined }, { next: null }, { next: [] }, { next: {} }, { next: { action: 'continue', method: 'GET', url } },
    ...[null, 1, true, {}, [], '', 'GET POST', 'GET\r\n'].map((method) => ({ next: { ...body.next, method } })),
    ...[null, 1, true, {}, [], '', '/relative', 'http://issuer.example/transactions/txn', 'http://127.0.0.1/transactions/txn',
      'javascript:alert(1)'].map((url) => ({ next: { ...body.next, url } })),
  ]) assert.equal(singleUseContinueError({ ...body, ...mutation }, 'completed'), false, JSON.stringify(mutation));
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
