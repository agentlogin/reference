import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import {
  createHandlers, MemoryCallbackStateStore, RelyingParty, RelyingPartyError,
  type CallbackStateStore, type PendingSignIn,
} from '../src/index.js';

let issuer: string;
let homeIssuer: string;
let key: CryptoKey;
let jwk: JWK;
let server: http.Server;
const token = { nonce: '', claims: {} as Record<string, unknown>, requests: 0, mode: 'success', expires: 300 as unknown };
let homeMetadataRequests = 0;
const clientId = 'response-validation-client';
const redirectUri = 'https://rp.example/callback?view=one&view=two';

before(async () => {
  const pair = await generateKeyPair('ES256');
  key = pair.privateKey;
  jwk = { ...await exportJWK(pair.publicKey), kid: 'test-key', alg: 'ES256', use: 'sig' };
  server = http.createServer(async (req, res) => {
    const send = (value: unknown, status = 200) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(value));
    };
    if (req.url === '/.well-known/openid-configuration' || req.url === '/home/.well-known/openid-configuration') {
      const home = req.url.startsWith('/home/');
      if (home) homeMetadataRequests += 1;
      send({
        issuer: home ? homeIssuer : issuer, authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/userinfo`,
        transaction_endpoint: `${issuer}/transactions`, agents_endpoint: `${issuer}/agents`,
        handle_domains: ['agents.example'], home_issuers: [homeIssuer],
        agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'],
      });
    } else if (req.url === '/jwks') send({ keys: [jwk] });
    else if (req.url === '/token') {
      token.requests += 1;
      if (token.mode === 'disconnect') { req.socket.destroy(); return; }
      if (token.mode === 'reject') { send({ error: 'invalid_grant' }, 400); return; }
      const idToken = await new SignJWT({ actor_type: 'agent', nonce: token.nonce, ...token.claims })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key' }).setIssuer(issuer).setAudience(clientId)
        .setSubject('test-agent').setIssuedAt().setExpirationTime('5m').sign(key);
      send({ id_token: idToken, access_token: 'test-access-token', token_type: 'Bearer', expires_in: token.expires, scope: 'openid' });
    } else send({}, 404);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  homeIssuer = `${issuer}/home`;
});
after(async () => { await new Promise<void>((resolve) => server.close(() => resolve())); });

const rpFor = (relay = false) => new RelyingParty({
  clientId, redirectUri, issuers: [{ issuer, relay }], allowInsecure: true,
  staticIssuers: { 'agents.example': issuer, 'home.example': homeIssuer }, stateSecret: 'response-validation-secret'.repeat(2),
});

async function start(rp: RelyingParty, handle?: string) {
  const backing = new MemoryCallbackStateStore();
  const counts = { claims: 0, signIns: 0, expiresAt: 0 };
  const callbackStore: CallbackStateStore = {
    register: (state, expiresAt) => backing.register(state, expiresAt),
    claim: (state) => { counts.claims += 1; return backing.claim(state); },
  };
  const handlers = createHandlers(rp, {
    callbackStore, onSignIn: (signIn) => { counts.signIns += 1; counts.expiresAt = signIn.accessTokenExpiresAt; return new Response('signed in'); }, log: () => {},
  });
  const response = await handlers.login(new Request(`https://rp.example/login${handle ? `?handle=${encodeURIComponent(handle)}` : ''}`));
  assert.equal(response.status, 302);
  const auth = new URL(response.headers.get('location')!);
  const state = auth.searchParams.get('state')!;
  const cookie = response.headers.get('set-cookie')!.split(';')[0]!;
  token.nonce = auth.searchParams.get('nonce')!;
  token.claims = {};
  token.mode = 'success';
  token.expires = 300;
  const params = () => new URLSearchParams({ state, iss: issuer, code: 'test-code' });
  const callback = (p: URLSearchParams, sessionCookie = cookie) => handlers.callback(new Request(
    `${redirectUri}&${p}`, { headers: { cookie: sessionCookie } },
  ));
  return { callback, params, counts, cookie };
}

test('malformed or unbound callbacks preserve state and cookie for the legitimate response', async (t) => {
  const cases: Array<[string, (p: URLSearchParams) => void, string?]> = [
    ['missing state', (p) => p.delete('state')],
    ['empty state', (p) => p.set('state', '')],
    ['wrong state', (p) => p.set('state', `${p.get('state')}!`)],
    ['missing issuer', (p) => p.delete('iss')],
    ['empty issuer', (p) => p.set('iss', '')],
    ['wrong issuer', (p) => p.set('iss', 'https://other.example')],
    ['no code or error', (p) => p.delete('code')],
    ['empty code', (p) => p.set('code', '')],
    ['empty error', (p) => { p.delete('code'); p.set('error', ''); }],
    ['code and error', (p) => p.set('error', 'access_denied')],
    ['code and empty error', (p) => p.set('error', '')],
    ['empty code and error', (p) => { p.set('code', ''); p.set('error', 'access_denied'); }],
    ['success with error description', (p) => p.set('error_description', 'denied')],
    ['success with error URI', (p) => p.set('error_uri', 'https://issuer.example/error')],
    ['missing cookie', () => {}, ''],
    ['tampered cookie', () => {}, 'invalid=value'],
  ];
  for (const member of ['state', 'iss', 'code', 'error', 'error_description', 'error_uri']) {
    cases.push([`duplicate ${member}`, (p) => {
      if (member.startsWith('error')) { p.delete('code'); p.set('error', 'access_denied'); }
      if (!p.has(member)) p.set(member, 'value');
      p.append(member, p.get(member)!);
    }]);
  }
  for (const [name, change, cookie] of cases) await t.test(name, async () => {
    const s = await start(rpFor());
    const p = s.params();
    change(p);
    const before = token.requests;
    const rejected = await s.callback(p, cookie);
    assert.equal(rejected.status, 400);
    assert.equal(rejected.headers.has('set-cookie'), false, 'an invalid response must preserve the pending cookie');
    assert.equal(s.counts.claims, 0, 'validate all protocol members and the session before consuming state');
    assert.equal(token.requests, before, 'an invalid response must not exchange a code');
    const valid = await s.callback(s.params());
    assert.equal(valid.status, 200, 'the original sign-in remains usable');
    assert.equal(s.counts.claims, 1);
    assert.equal(s.counts.signIns, 1);
    assert.equal(token.requests, before + 1);
  });
});

test('valid error responses consume state and never exchange a code', async () => {
  const s = await start(rpFor());
  const params = s.params();
  params.delete('code');
  params.set('error', 'access_denied');
  params.set('error_description', 'owner_declined');
  params.set('error_uri', 'https://issuer.example/error');
  const before = token.requests;
  const response = await s.callback(params);
  assert.equal(response.status, 400);
  assert.match(await response.text(), /owner declined/);
  assert.match(response.headers.get('set-cookie')!, /Max-Age=0/);
  assert.equal(s.counts.claims, 1);
  assert.equal(token.requests, before);
  assert.match(await (await s.callback(s.params())).text(), /duplicate_callback/);
  assert.equal(s.counts.signIns, 0);
  assert.equal(token.requests, before);
});

test('failed and uncertain exchanges leave callback state consumed', async (t) => {
  for (const mode of ['reject', 'disconnect']) await t.test(mode, async () => {
    const s = await start(rpFor());
    token.mode = mode;
    const before = token.requests;
    const response = await s.callback(s.params());
    assert.equal(response.status, 502);
    assert.match(await response.text(), /token_request_failed/);
    assert.match(await (await s.callback(s.params())).text(), /duplicate_callback/);
    assert.equal(token.requests, before + 1);
    assert.equal(s.counts.signIns, 0);
  });
});

test('complete enforces callback shape for callers managing their own state', async (t) => {
  const rp = rpFor();
  const pending: PendingSignIn = { state: 'raw-state', nonce: 'nonce', verifier: 'verifier', issuer };
  for (const suffix of ['error=access_denied', 'error=', 'error_description=wrong', 'error_uri=wrong', 'error_uri=a&error_uri=b']) {
    await t.test(suffix, async () => {
      const before = token.requests;
      await assert.rejects(rp.complete({ pending, params: new URLSearchParams(`state=raw-state&iss=${encodeURIComponent(issuer)}&code=code&${suffix}`) }),
        (e: unknown) => e instanceof RelyingPartyError && e.code === 'invalid_request');
      assert.equal(token.requests, before);
    });
  }
});

test('complete binds the returned handle to pending loginHint with Section 2.1 comparison', async (t) => {
  for (const [email, accepted] of [
    ['Scout@AGENTS.EXAMPLE', true], ['scout@agents.example', false], ['other@agents.example', false],
  ] as const) await t.test(email, async () => {
    const s = await start(rpFor(), 'Scout@agents.example');
    token.claims = { email, email_verified: true };
    const params = s.params();
    params.set('login_hint', email); // An untrusted callback cannot replace the expected handle.
    const response = await s.callback(params);
    assert.equal(response.status, accepted ? 200 : 400);
    if (!accepted) {
      assert.match(await response.text(), /handle_binding_failed/);
      assert.match(await (await s.callback(params)).text(), /duplicate_callback/);
    }
    assert.equal(s.counts.signIns, accepted ? 1 : 0);
  });
});

test('Relay tokens require discovery of returned email or the pre-bound handle', async (t) => {
  const cases = [
    { name: 'no handle', accepted: false },
    { name: 'callback hint only', callbackHint: 'Scout@home.example', accepted: false },
    { name: 'bound handle without email', handle: 'Scout@home.example', accepted: true },
    { name: 'bound handle designates another issuer', handle: 'Scout@agents.example', accepted: false },
    { name: 'returned handle', email: 'Scout@home.example', accepted: true },
    { name: 'conflicting bound and returned handles', handle: 'Scout@home.example', email: 'Other@home.example', accepted: false },
  ];
  for (const scenario of cases) await t.test(scenario.name, async () => {
    const s = await start(rpFor(true), scenario.handle);
    token.claims = { home_iss: homeIssuer, ...(scenario.email ? { email: scenario.email, email_verified: true } : {}) };
    const params = s.params();
    if (scenario.callbackHint) params.set('login_hint', scenario.callbackHint);
    const before = homeMetadataRequests;
    const response = await s.callback(params);
    assert.equal(response.status, scenario.accepted ? 200 : 400);
    if (!scenario.accepted) assert.match(await response.text(), /handle_binding_failed/);
    else assert.equal(homeMetadataRequests, before + 1, 'discovery also verifies the Home Issuer metadata');
    assert.equal(s.counts.signIns, scenario.accepted ? 1 : 0);
  });
});

test('token responses require a bounded integer expiry without fallback lifetimes', async () => {
  for (const expires of [undefined, null, '600', 0, -1, 0.5, 601, 3600]) {
    const s = await start(rpFor()); token.expires = expires;
    const rejected = await s.callback(s.params());
    assert.equal(rejected.status, 502, String(expires));
    assert.equal(s.counts.signIns, 0);
  }
});

test('asynchronous validation cannot renew a token or return one that expired during validation', async () => {
  const realNow = Date.now;
  let clock = realNow();
  Date.now = () => clock;
  try {
    for (const lifetime of [300, 10]) {
      const rp = rpFor();
      const validate = rp.validateIdToken.bind(rp);
      rp.validateIdToken = async (...args) => { const claims = await validate(...args); clock += 30_000; return claims; };
      const s = await start(rp); token.expires = lifetime;
      const requestStarted = Math.floor(clock / 1000);
      const response = await s.callback(s.params());
      assert.equal(response.status, lifetime === 300 ? 200 : 400);
      if (lifetime === 300) assert.equal(s.counts.expiresAt, requestStarted + lifetime);
      else assert.equal(s.counts.signIns, 0);
    }
  } finally { Date.now = realNow; }
});
