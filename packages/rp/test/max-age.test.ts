import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import {
  createHandlers, MemoryCallbackStateStore, RelyingParty, RelyingPartyError, seal, unseal,
  type IdTokenValidationOptions, type PendingSignIn,
} from '../src/index.js';

let issuer: string;
let key: CryptoKey;
let jwk: JWK;
let server: http.Server;
let tokenNonce = 'nonce';
let tokenClaims: Record<string, unknown> = {};
let onMetadata: (() => void) | undefined;
const clientId = 'max-age-client';
const redirectUri = 'https://rp.example/callback';
const secret = 'max-age-pending-secret'.repeat(2);

before(async () => {
  const pair = await generateKeyPair('ES256');
  key = pair.privateKey;
  jwk = { ...await exportJWK(pair.publicKey), kid: 'age-key', alg: 'ES256', use: 'sig' };
  server = http.createServer(async (req, res) => {
    const send = (value: unknown, status = 200) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(value));
    };
    if (req.url === '/.well-known/openid-configuration') {
      onMetadata?.();
      send({
        issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/userinfo`,
        transaction_endpoint: `${issuer}/transactions`, agents_endpoint: `${issuer}/agents`,
        handle_domains: ['agents.example'], agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'],
      });
    } else if (req.url === '/jwks') send({ keys: [jwk] });
    else if (req.url === '/token') send({
      id_token: await mint(tokenClaims, tokenNonce), access_token: 'access-token', token_type: 'Bearer', expires_in: 300,
    });
    else send({}, 404);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => { await new Promise<void>((resolve) => server.close(() => resolve())); });

const rpFor = (maxAge?: number) => new RelyingParty({
  clientId, redirectUri, issuers: [issuer], allowInsecure: true, stateSecret: secret, maxAge,
});
async function mint(claims: Record<string, unknown> = {}, nonce = 'nonce') {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ actor_type: 'agent', nonce, iss: issuer, aud: clientId, sub: 'agent', iat: now, exp: now + 300, ...claims })
    .setProtectedHeader({ alg: 'ES256', kid: 'age-key' }).sign(key);
}
const rejectedToken = (e: unknown) => e instanceof RelyingPartyError && e.code === 'invalid_id_token';
const context = (maxAge: number, authenticationRequestedAt = Math.floor(Date.now() / 1000)): IdTokenValidationOptions => ({
  issuer, clientId, nonce: 'nonce', maxAge, authenticationRequestedAt,
});

test('login_required is a distinct consumed callback error and does not exchange a code', async () => {
  const rp = rpFor(1);
  const handlers = createHandlers(rp, { callbackStore: new MemoryCallbackStateStore(), onSignIn: () => { throw new Error('must not sign in'); } });
  const started = await handlers.login(new Request('https://rp.example/login'));
  const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
  const cookie = started.headers.get('set-cookie')!.split(';')[0]!;
  // Any attempt to do discovery/exchange after a validated error callback is a regression.
  (rp as any).metadata = async () => { throw new Error('must not contact issuer'); };
  const callback = () => new Request(`${redirectUri}?${new URLSearchParams({ state, iss: issuer, error: 'login_required', error_description: '<script>untrusted</script>' })}`, { headers: { cookie } });
  const response = await handlers.callback(callback());
  assert.equal(response.status, 400);
  const body = await response.text();
  assert.match(body, /login_required/);
  assert.match(body, /Start a new sign-in/);
  assert.doesNotMatch(body, /untrusted/);
  assert.match(await (await handlers.callback(callback())).text(), /duplicate_callback/);
});

// Date-only mocking leaves socket I/O and test runner timers real, while making every age boundary exact.
test('begin sends the trusted age policy and records request time after discovery', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const rp = rpFor(30);
  onMetadata = () => t.mock.timers.tick(10_000);
  try {
    const initial = Math.floor(Date.now() / 1000);
    const begun = await rp.begin();
    assert.equal(new URL(begun.url).searchParams.get('max_age'), '30');
    assert.equal(begun.pending.maxAge, 30);
    assert.equal(begun.pending.authenticationRequestedAt, initial + 10);
    const fresh = await rp.begin({ maxAge: 0 });
    assert.equal(new URL(fresh.url).searchParams.get('max_age'), '0');
    assert.equal(fresh.pending.maxAge, 0);
    const plain = await rpFor().begin();
    assert.equal(new URL(plain.url).searchParams.has('max_age'), false);
    assert.equal(plain.pending.maxAge, undefined);
    assert.equal(plain.pending.authenticationRequestedAt, undefined);
  } finally { onMetadata = undefined; }
});

test('configured and per-request maxAge reject malformed values without coercion', async () => {
  for (const value of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '5', null]) {
    assert.throws(() => rpFor(value as number), /maxAge/);
    await assert.rejects(rpFor().begin({ maxAge: value as number }),
      (e: unknown) => e instanceof RelyingPartyError && e.code === 'invalid_request');
  }
});

test('positive max_age has an exact age bound, required auth_time and no hidden tolerance', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Math.floor(Date.now() / 1000) * 1000 });
  const now = Math.floor(Date.now() / 1000);
  const rp = rpFor();
  for (const age of [0, 9, 10]) await rp.validateIdToken(await mint({ auth_time: now - age }), context(10));
  for (const authTime of [undefined, null, '1', now - 11, now + 1, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(rp.validateIdToken(await mint({ auth_time: authTime }), context(10)), rejectedToken);
  }
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: now, iat: now - 1 }), context(10)), rejectedToken);
  // A client which did not request max_age still accepts a valid token without auth_time.
  await rp.validateIdToken(await mint(), { issuer, clientId, nonce: 'nonce' });
});

test('fractional auth_time follows NumericDate and exact age, request and future boundaries', async (t) => {
  const seconds = Math.floor(Date.now() / 1000);
  t.mock.timers.enable({ apis: ['Date'], now: seconds * 1000 + 750 });
  const now = Date.now() / 1000;
  const rp = rpFor();
  for (const authTime of [now, now - 0.5, now - 10]) {
    await rp.validateIdToken(await mint({ auth_time: authTime, iat: now }), context(10, seconds));
  }
  // One millisecond past the age bound is stale; a fraction of a second is not rounded away.
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: now - 10.001, iat: now }), context(10, seconds)), rejectedToken);
  // A future auth_time remains invalid even when its matching iat is inside the iat clock tolerance.
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: now + 0.001, iat: now + 0.001 }), context(10, seconds)), rejectedToken);
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: now, iat: now - 0.001 }), context(10, seconds)), rejectedToken);
  await rp.validateIdToken(await mint({ auth_time: seconds + 0.25, iat: now }), context(0, seconds));
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: seconds - 0.001, iat: now }), context(0, seconds)), rejectedToken);
});

test('max_age zero binds authentication to the request and survives a long Owner wait', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const started = Math.floor(Date.now() / 1000);
  const rp = rpFor(0);
  const begun = await rp.begin();
  tokenNonce = begun.pending.nonce;
  tokenClaims = { auth_time: started };
  t.mock.timers.tick(3_600_000);
  const completed = await rp.complete({ pending: begun.pending, params: new URLSearchParams({ state: begun.pending.state, iss: issuer, code: 'code' }) });
  assert.equal(completed.claims.auth_time, started, 'approval/delivery delay does not refresh authentication');
  await rp.validateIdToken(await mint({ auth_time: started }), context(0, started));
  for (const authTime of [started - 1, Math.floor(Date.now() / 1000) + 1]) {
    await assert.rejects(rp.validateIdToken(await mint({ auth_time: authTime }), context(0, started)), rejectedToken);
  }
  await assert.rejects(rp.validateIdToken(await mint({ auth_time: started }), context(0, Math.floor(Date.now() / 1000) + 1)), rejectedToken);
});

test('age and token expiry are rechecked after asynchronous handle discovery', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Math.floor(Date.now() / 1000) * 1000 });
  const rp = rpFor();
  t.mock.method(rp, 'resolve', async () => {
    await Promise.resolve();
    t.mock.timers.tick(1_000);
    return issuer;
  });
  const started = Math.floor(Date.now() / 1000);
  const token = await mint({ auth_time: started - 10, email: 'scout@agents.example', email_verified: true });
  await assert.rejects(rp.validateIdToken(token, context(10, started)), rejectedToken);
  const expiring = await mint({ exp: Math.floor(Date.now() / 1000) + 1, email: 'scout@agents.example', email_verified: true });
  await assert.rejects(rp.validateIdToken(expiring, { issuer, clientId, nonce: 'nonce' }), rejectedToken);
});

test('sealed age policy round-trips and malformed pairs fail closed before token exchange', async () => {
  const rp = rpFor(0);
  const pending = (await rp.begin()).pending;
  const opened = await unseal(secret, await seal(secret, pending, 300));
  assert.deepEqual(opened, pending);
  const malformed: Array<Record<string, unknown>> = [
    { maxAge: undefined }, { authenticationRequestedAt: undefined },
    { maxAge: null }, { maxAge: '0' }, { maxAge: -1 }, { maxAge: 1.5 },
    { authenticationRequestedAt: null }, { authenticationRequestedAt: '1' },
    { authenticationRequestedAt: -1 }, { authenticationRequestedAt: 1.5 },
    { authenticationRequestedAt: Number.MAX_SAFE_INTEGER + 1 },
  ];
  for (const change of malformed) {
    const broken = { ...pending, ...change } as PendingSignIn;
    assert.equal(await unseal(secret, await seal(secret, broken, 300)), null);
    assert.throws(() => rp.preflightCallback({ pending: broken, params: new URLSearchParams({ state: broken.state, iss: issuer, code: 'code' }) }),
      (e: unknown) => e instanceof RelyingPartyError && e.code === 'invalid_state');
    await assert.rejects(rp.validateIdToken(await mint(), { issuer, clientId, nonce: 'nonce', maxAge: broken.maxAge, authenticationRequestedAt: broken.authenticationRequestedAt }), rejectedToken);
  }
  const sealed = await seal(secret, pending, 300);
  const parts = sealed.split('.');
  parts[3] = `${parts[3]![0] === 'A' ? 'B' : 'A'}${parts[3]!.slice(1)}`;
  assert.equal(await unseal(secret, parts.join('.')), null);
});

test('login and callback query parameters cannot weaken the configured age policy', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  for (const initiated of [false, true]) {
    let signedIn = false;
    const handlers = createHandlers(rpFor(10), {
      callbackStore: new MemoryCallbackStateStore(), onSignIn: () => { signedIn = true; return new Response('signed in'); }, log: () => {},
    });
    const response = await handlers.login(new Request(`https://rp.example/login?max_age=999999${initiated ? `&iss=${encodeURIComponent(issuer)}` : ''}`));
    assert.equal(response.status, 302);
    const auth = new URL(response.headers.get('location')!);
    assert.equal(auth.searchParams.get('max_age'), '10');
    const cookie = response.headers.get('set-cookie')!.split(';')[0]!;
    const pending = await unseal(secret, cookie.slice(cookie.indexOf('=') + 1));
    assert.equal(pending?.maxAge, 10);
    tokenNonce = auth.searchParams.get('nonce')!;
    tokenClaims = { auth_time: Math.floor(Date.now() / 1000) - 11 };
    const params = new URLSearchParams({ state: auth.searchParams.get('state')!, iss: issuer, code: 'code', max_age: '999999', authenticationRequestedAt: '0' });
    const callback = await handlers.callback(new Request(`${redirectUri}?${params}`, { headers: { cookie } }));
    assert.equal(callback.status, 400);
    assert.match(await callback.text(), /invalid_id_token/);
    assert.equal(signedIn, false);
  }
});
