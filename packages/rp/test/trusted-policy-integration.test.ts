import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { IssuerMetadata } from 'agentlogin';
import {
  createHandlers, MemoryCallbackStateStore, RelyingParty, RelyingPartyError,
  type PendingSignIn, type RelyingPartyOptions, type SignIn,
} from '../src/index.js';
import { TrustedProviderPolicy, type IssuerAcceptancePolicy } from '../src/trusted-providers.js';

const clientId = 'https://rp.example/agent-login/client.json';
const redirectUri = 'https://rp.example/callback?view=one&view=two';
const handle = 'Scout@agents.example';
const policyUrl = 'https://policy.example/trusted-providers/v1.json';
const publishedIssuer = 'https://issuer.example';

const rejectsWith = (code: string) => (error: unknown) => error instanceof RelyingPartyError && error.code === code;

/**
 * The policy's transport is injected, but its parser, cache and acceptance checks are real. The adapter
 * changes only the fixture's issuer origin so production policy validation remains HTTPS-only while
 * RP metadata, token, JWKS and UserInfo requests use a real loopback HTTP server and signed JWTs.
 */
async function fixture(t: TestContext) {
  const pair = await generateKeyPair('ES256');
  const jwk = { ...await exportJWK(pair.publicKey), kid: 'policy-fixture', alg: 'ES256', use: 'sig' };
  const requests: Array<{ path: string; authorization?: string; body: string }> = [];
  const hooks = new Map<string, () => void | Promise<void>>();
  const issuedAt = Date.now();
  let clock = issuedAt;
  let revision = 1;
  let accepted = true;
  let reviewedDomains = ['agents.example'];
  let unavailable = false;
  let policyFetches = 0;
  let policyFetchHook: (() => void | Promise<void>) | undefined;
  let nonce = '';
  let tokenLifetime = 300;
  let claims: Record<string, unknown> = { email: handle, email_verified: true };
  let userinfo: Record<string, unknown> = { sub: 'fixture-agent' };
  let metadataOverrides: Record<string, unknown> = {};
  let issuer: string;
  const metadata = () => ({
    issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/userinfo`,
    transaction_endpoint: `${issuer}/transactions`, agents_endpoint: `${issuer}/agents`,
    handle_domains: ['agents.example', 'unreviewed.example'], agent_key_algs_supported: ['ES256'],
    id_token_signing_alg_values_supported: ['ES256'], agent_login_versions_supported: ['1.0'], ...metadataOverrides,
  });
  const sign = (tokenNonce = nonce, tokenClaims = claims, audience = clientId) => new SignJWT({ actor_type: 'agent', nonce: tokenNonce, ...tokenClaims })
    .setProtectedHeader({ alg: 'ES256', kid: jwk.kid }).setIssuer(issuer).setAudience(audience)
    .setSubject('fixture-agent').setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) + tokenLifetime).sign(pair.privateKey);
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const path = req.url!;
    requests.push({ path, authorization: req.headers.authorization, body: Buffer.concat(chunks).toString('utf8') });
    const hook = hooks.get(path);
    hooks.delete(path);
    if (hook) await hook();
    const send = (body: unknown, status = 200) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (path === '/.well-known/openid-configuration') send(metadata());
    else if (path === '/token') send({ id_token: await sign(), access_token: 'fixture-access-token', token_type: 'Bearer', expires_in: 300, scope: 'openid email' });
    else if (path === '/jwks') send({ keys: [jwk] });
    else if (path === '/userinfo') send(userinfo);
    else send({}, 404);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const trusted = new TrustedProviderPolicy({
    url: policyUrl, now: () => clock,
    fetch: async (url, options) => {
      policyFetches += 1;
      assert.equal(String(url), policyUrl);
      assert.equal(options.allowPrivate, false);
      assert.equal(options.maxRedirects, 0);
      if (unavailable) throw new Error('publisher unavailable');
      const hook = policyFetchHook;
      policyFetchHook = undefined;
      if (hook) await hook();
      return { url: policyUrl, status: 200, headers: {}, redirects: [], body: Buffer.from(JSON.stringify({
        version: 1, programme: 'agentlogin-trusted-providers', profile: 'agent-login-core-1.0-draft-0.2-direct-es256', status: 'active', revision,
        issuedAt: new Date(issuedAt).toISOString(), expiresAt: new Date(issuedAt + 86_400_000).toISOString(),
        providers: accepted ? [{ issuer: publishedIssuer, handleDomains: reviewedDomains,
          specRevision: '1234567890abcdef1234567890abcdef12345678', reviewUrl: 'https://policy.example/reviews/issuer',
          reviewExpiresAt: new Date(issuedAt + 7 * 86_400_000).toISOString() }] : [],
      })) };
    },
  });
  const issuerPolicy: IssuerAcceptancePolicy = {
    async assertAccepted(candidate, expectedHandle) {
      if (candidate !== issuer) throw new RelyingPartyError('issuer_not_accepted', 'unexpected fixture issuer');
      await trusted.assertAccepted(publishedIssuer, expectedHandle);
    },
  };
  const options = (): RelyingPartyOptions => ({
    clientId, redirectUri, issuers: [], issuerPolicy, allowInsecure: true,
    staticIssuers: { 'agents.example': issuer, 'unreviewed.example': issuer },
    stateSecret: 'trusted-policy-integration-state-secret',
  });
  const rp = (overrides: Partial<RelyingPartyOptions> = {}) => new RelyingParty({ ...options(), ...overrides });
  const pending = (): PendingSignIn => ({ issuer, state: 'fixture-state', nonce: 'fixture-nonce', verifier: 'fixture-verifier', loginHint: handle });
  const params = (p: PendingSignIn) => new URLSearchParams({ state: p.state, iss: p.issuer, code: 'fixture-code' });
  async function start(party = rp(), loginHandle = handle) {
    const signedIn: SignIn[] = [];
    const handlers = createHandlers(party, { callbackStore: new MemoryCallbackStateStore(), log: () => {},
      onSignIn: (value) => { signedIn.push(value); return new Response('signed in'); } });
    const response = await handlers.login(new Request(`https://rp.example/login?handle=${encodeURIComponent(loginHandle)}`));
    assert.equal(response.status, 302, await response.clone().text());
    const auth = new URL(response.headers.get('location')!);
    nonce = auth.searchParams.get('nonce')!;
    const cookie = response.headers.get('set-cookie')!.split(';')[0]!;
    const query = () => new URLSearchParams({ state: auth.searchParams.get('state')!, iss: issuer, code: 'fixture-code' });
    const callback = (p = query()) => handlers.callback(new Request(`${redirectUri}&${p}`, { headers: { cookie } }));
    return { party, signedIn, query, callback };
  }
  return { issuer, issuerPolicy, options, rp, requests, hooks, start, pending, params, sign, metadata,
    setNonce(value: string) { nonce = value; },
    setTokenLifetime(value: number) { tokenLifetime = value; },
    setClaims(value: Record<string, unknown>) { claims = value; },
    setUserInfo(value: Record<string, unknown>) { userinfo = value; },
    setMetadata(value: Record<string, unknown>) { metadataOverrides = value; },
    setReviewedDomains(value: string[]) { reviewedDomains = value; },
    remove() { accepted = false; revision += 1; clock += 60_001; },
    restore() { accepted = true; revision += 1; clock += 60_001; },
    failRefresh() { unavailable = true; clock += 60_001; },
    expirePolicyCache() { clock += 60_001; },
    onNextPolicyFetch(hook: () => void | Promise<void>) { policyFetchHook = hook; },
    policyFetches: () => policyFetches,
  };
}

test('an explicitly selected policy admits discovered issuers without a static issuer list', async (t) => {
  const f = await fixture(t);
  const s = await f.start();
  assert.equal((await s.callback()).status, 200);
  assert.equal(s.signedIn.length, 1);
  assert.equal(s.signedIn[0]!.agent.handle, handle);
  const live = s.party.liveCheckOf(s.signedIn[0]!);
  assert.equal(live.handle, handle);
  assert.deepEqual(await s.party.recheck(live), { sub: 'fixture-agent' });
  assert.equal(f.requests.find((r) => r.path === '/userinfo')?.authorization, 'Bearer fixture-access-token');
  const initiated = await s.party.beginInitiated({ iss: f.issuer, loginHint: handle });
  assert.equal(initiated.pending.issuer, f.issuer);
  assert.equal(initiated.pending.loginHint, handle);
  assert.equal(f.policyFetches(), 1, 'fresh feed data may be reused across separately guarded operations');
});

test('an initial policy denial prevents every issuer request, including for configured Registered Clients', async (t) => {
  const f = await fixture(t);
  const rp = f.rp({ issuers: [{ issuer: f.issuer, clientId: 'registered-client', clientSecret: 'registered-secret' }] });
  f.remove();
  const pending = f.pending();
  const jwt = await f.sign(pending.nonce);
  const operations = [
    () => rp.begin({ handle }),
    () => rp.begin({ issuer: f.issuer, handle }),
    () => rp.beginInitiated({ iss: f.issuer, loginHint: handle }),
    () => rp.complete({ pending, params: f.params(pending) }),
    () => rp.validateIdToken(jwt, { issuer: f.issuer, clientId, nonce: pending.nonce, expectedHandle: handle }),
    () => rp.recheck({ issuer: f.issuer, sub: 'fixture-agent', handle, accessToken: 'do-not-send', accessTokenExpiresAt: Date.now() / 1000 + 300 }),
  ];
  for (const operation of operations) await assert.rejects(operation, rejectsWith('issuer_not_accepted'));
  assert.deepEqual(f.requests, [], 'local configuration and secrets must not bypass the selected feed');
});

test('policy admission requires the exact reviewed handle domain and a bound known handle', async (t) => {
  const f = await fixture(t);
  const rp = f.rp({ issuers: [f.issuer] });
  for (const candidate of ['Scout@unreviewed.example', 'Scout@sub.agents.example']) {
    await assert.rejects(rp.begin({ issuer: f.issuer, handle: candidate }), rejectsWith('issuer_not_accepted'));
  }
  await assert.rejects(rp.begin({ issuer: f.issuer }), rejectsWith('handle_required'));
  await assert.rejects(rp.beginInitiated({ iss: f.issuer }), rejectsWith('handle_required'));
  assert.deepEqual(f.requests, []);
});

test('admitted issuers must also advertise the selected direct ES256 protocol profile', async (t) => {
  const invalidMetadata: Array<[string, Record<string, unknown>]> = [
    ['wrong version', { agent_login_versions_supported: ['2.0'] }],
    ['missing version', { agent_login_versions_supported: undefined }],
    ['malformed versions', { agent_login_versions_supported: ['1.0', 1] }],
    ['agent keys omit ES256', { agent_key_algs_supported: ['Ed25519'] }],
    ['agent keys advertise unsupported algorithm', { agent_key_algs_supported: ['ES256', 'RS256'] }],
    ['ID Tokens omit ES256', { id_token_signing_alg_values_supported: ['Ed25519'] }],
    ['ID Tokens advertise unsupported algorithm', { id_token_signing_alg_values_supported: ['ES256', 'HS256'] }],
    ['missing ID Token algorithms', { id_token_signing_alg_values_supported: undefined }],
    ['wrong handle domain', { handle_domains: ['other.example'] }],
    ['wildcard excludes its own apex', { handle_domains: ['*.agents.example'] }],
    ['malformed handle domains', { handle_domains: ['agents.example', 42] }],
    ['Relay', { home_issuers: ['*'] }],
    ['empty Relay declaration', { home_issuers: [] }],
  ];
  for (const [name, metadata] of invalidMetadata) await t.test(name, async (child) => {
    const f = await fixture(child);
    const rp = f.rp();
    f.setMetadata(metadata);
    await assert.rejects(rp.begin({ handle }), rejectsWith('issuer_not_accepted'));
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0]!.path, '/.well-known/openid-configuration');
    const jwt = await f.sign('preloaded-metadata');
    await assert.rejects(rp.validateIdToken(jwt, {
      issuer: f.issuer, clientId, nonce: 'preloaded-metadata', expectedHandle: handle,
      metadata: f.metadata() as IssuerMetadata,
    }), rejectsWith('issuer_not_accepted'));
    assert.equal(f.requests.length, 1, 'preloaded metadata must pass the same gate before any JWKS request');
  });
});

test('profile-compatible algorithm lists and metadata wildcards retain exact feed-domain restrictions', async (t) => {
  const f = await fixture(t);
  const reviewedHandle = 'Scout@reviewed.agents.example';
  f.setReviewedDomains(['reviewed.agents.example']);
  f.setClaims({ email: reviewedHandle, email_verified: true });
  f.setMetadata({ agent_login_versions_supported: ['1.0', '2.0'], agent_key_algs_supported: ['ES256', 'Ed25519'],
    id_token_signing_alg_values_supported: ['ES256', 'Ed25519'], handle_domains: ['*.agents.example'] });
  const s = await f.start(f.rp({ staticIssuers: { 'reviewed.agents.example': f.issuer, 'unreviewed.agents.example': f.issuer } }), reviewedHandle);
  assert.equal((await s.callback()).status, 200);
  assert.equal(s.signedIn.length, 1);
  const before = f.requests.length;
  await assert.rejects(s.party.begin({ issuer: f.issuer, handle: 'Scout@unreviewed.agents.example' }), rejectsWith('issuer_not_accepted'));
  assert.equal(f.requests.length, before, 'a broader metadata wildcard must not broaden reviewed feed domains');
});

test('a later metadata response advertising a Relay stops standalone validation before JWKS retrieval', async (t) => {
  const f = await fixture(t);
  const rp = f.rp();
  const jwt = await f.sign('changing-profile');
  f.hooks.set('/.well-known/openid-configuration', () => {
    f.hooks.set('/.well-known/openid-configuration', () => f.setMetadata({ home_issuers: ['*'] }));
  });
  await assert.rejects(rp.validateIdToken(jwt, {
    issuer: f.issuer, clientId, nonce: 'changing-profile', expectedHandle: handle,
  }), rejectsWith('issuer_not_accepted'));
  assert.deepEqual(f.requests.map((r) => r.path), ['/.well-known/openid-configuration', '/.well-known/openid-configuration']);
});

test('removal during metadata cannot return an authorization redirect or start a code exchange', async (t) => {
  for (const stage of ['begin', 'complete'] as const) await t.test(stage, async (child) => {
    const f = await fixture(child);
    const rp = f.rp();
    const begun = stage === 'complete' ? await rp.begin({ handle }) : undefined;
    f.hooks.set('/.well-known/openid-configuration', () => f.remove());
    if (begun) {
      f.setNonce(begun.pending.nonce);
      await assert.rejects(rp.complete({ pending: begun.pending, params: f.params(begun.pending) }), rejectsWith('issuer_not_accepted'));
    } else await assert.rejects(rp.begin({ handle }), rejectsWith('issuer_not_accepted'));
    assert.equal(f.requests.filter((r) => r.path === '/token').length, 0);
  });
});

test('removal during the explicit issuer handle-discovery check prevents the metadata request', async (t) => {
  const f = await fixture(t);
  const rp = f.rp();
  const resolve = rp.resolve.bind(rp);
  let discovered = false;
  rp.resolve = async (candidate) => {
    const result = await resolve(candidate);
    discovered = true;
    f.remove();
    return result;
  };
  await assert.rejects(rp.begin({ issuer: f.issuer, handle }), rejectsWith('issuer_not_accepted'));
  assert.equal(discovered, true);
  assert.deepEqual(f.requests, [], 'a removal observed after discovery must stop the next issuer request');
});

test('removal during either standalone validation metadata fetch prevents further metadata and JWKS requests', async (t) => {
  for (const removeOnMetadata of [1, 2]) await t.test(`metadata response ${removeOnMetadata}`, async (child) => {
    const f = await fixture(child);
    const rp = f.rp();
    const jwt = await f.sign('metadata-wait');
    let metadataRequests = 0;
    const duringMetadata = () => {
      metadataRequests += 1;
      if (metadataRequests === removeOnMetadata) f.remove();
      else f.hooks.set('/.well-known/openid-configuration', duringMetadata);
    };
    f.hooks.set('/.well-known/openid-configuration', duringMetadata);
    await assert.rejects(rp.validateIdToken(jwt, { issuer: f.issuer, clientId, nonce: 'metadata-wait', expectedHandle: handle }), rejectsWith('issuer_not_accepted'));
    assert.equal(metadataRequests, removeOnMetadata);
    assert.equal(f.requests.length, removeOnMetadata, 'no extra metadata or JWKS request may follow the removal');
    assert.equal(f.requests.filter((r) => r.path === '/jwks').length, 0);
  });
});

test('revocation before a valid callback consumes its claim without contacting the issuer', async (t) => {
  const f = await fixture(t);
  const s = await f.start();
  const before = f.requests.length;
  f.remove();
  const rejected = await s.callback();
  assert.equal(rejected.status, 400);
  assert.match(await rejected.text(), /issuer_not_accepted/);
  assert.match(rejected.headers.get('set-cookie')!, /Max-Age=0/);
  assert.equal(f.requests.length, before);
  f.restore();
  const replay = await s.callback();
  assert.match(await replay.text(), /duplicate_callback/);
  assert.equal(f.requests.length, before, 'restored trust must not reopen a consumed callback');
  assert.equal(s.signedIn.length, 0);
});

test('removal while token exchange or JWKS retrieval is in flight blocks final sign-in', async (t) => {
  for (const path of ['/token', '/jwks']) await t.test(path, async (child) => {
    const f = await fixture(child);
    const s = await f.start();
    f.hooks.set(path, () => f.remove());
    const rejected = await s.callback();
    assert.equal(rejected.status, 400);
    assert.match(await rejected.text(), /issuer_not_accepted/);
    assert.equal(s.signedIn.length, 0);
    assert.equal(f.requests.filter((r) => r.path === path).length, 1);
    const before = f.requests.length;
    assert.match(await (await s.callback()).text(), /duplicate_callback/);
    assert.equal(f.requests.length, before);
  });
});

test('standalone signed-token validation rechecks admission after asynchronous JWKS retrieval', async (t) => {
  const f = await fixture(t);
  const rp = f.rp();
  const jwt = await f.sign('standalone-nonce');
  f.hooks.set('/jwks', () => f.remove());
  await assert.rejects(rp.validateIdToken(jwt, { issuer: f.issuer, clientId, nonce: 'standalone-nonce', expectedHandle: handle }), rejectsWith('issuer_not_accepted'));
  assert.equal(f.requests.filter((r) => r.path === '/jwks').length, 1);
});

test('UserInfo success cannot authorize an action after admission is removed during the request', async (t) => {
  const f = await fixture(t);
  const s = await f.start();
  assert.equal((await s.callback()).status, 200);
  const live = s.party.liveCheckOf(s.signedIn[0]!);
  f.hooks.set('/userinfo', () => f.remove());
  await assert.rejects(s.party.recheck(live), rejectsWith('issuer_not_accepted'));
  const before = f.requests.length;
  await assert.rejects(s.party.recheck(live), rejectsWith('issuer_not_accepted'));
  assert.equal(f.requests.length, before, 'subsequent action checks must fail before bearer transmission');
});

test('a stale policy whose publisher fails does not produce a successful callback', async (t) => {
  const f = await fixture(t);
  const s = await f.start();
  f.hooks.set('/token', () => f.failRefresh());
  const rejected = await s.callback();
  assert.equal(rejected.status, 503);
  assert.match(await rejected.text(), /issuer_policy_unavailable/);
  assert.equal(s.signedIn.length, 0);
  assert.match(await (await s.callback()).text(), /duplicate_callback/);
});

test('ID Token expiry and authentication freshness are checked after the final policy refresh', async (t) => {
  for (const deadline of ['ID Token', 'authentication age'] as const) await t.test(deadline, async (child) => {
    const f = await fixture(child);
    const s = await f.start(f.rp(deadline === 'authentication age' ? { maxAge: 5 } : {}));
    if (deadline === 'ID Token') f.setTokenLifetime(5);
    else f.setClaims({ email: handle, email_verified: true, auth_time: Math.floor(Date.now() / 1000) });
    const realNow = Date.now;
    const before = realNow();
    let refreshedAfterJwks = false;
    f.hooks.set('/jwks', () => {
      f.expirePolicyCache();
      f.onNextPolicyFetch(async () => {
        // The signed token is already received and its keys fetched. Simulate time spent waiting for
        // the final policy refresh, leaving the 300-second access token valid throughout.
        await Promise.resolve();
        Date.now = () => before + 6_000;
        refreshedAfterJwks = true;
      });
    });
    try {
      const rejected = await s.callback();
      assert.equal(rejected.status, 400);
      assert.match(await rejected.text(), /invalid_id_token/);
      assert.equal(refreshedAfterJwks, true);
      assert.equal(s.signedIn.length, 0);
      assert.equal(f.policyFetches(), 2, 'the expiry must occur during a real policy refresh, not a stubbed token validator');
      assert.match(await (await s.callback()).text(), /duplicate_callback/);
    } finally { Date.now = realNow; }
  });
});

test('normal callback issuer, state and duplicate-parameter validation still precedes claim consumption', async (t) => {
  for (const mutation of ['issuer', 'state', 'duplicate-code']) await t.test(mutation, async (child) => {
    const f = await fixture(child);
    const s = await f.start();
    const invalid = s.query();
    if (mutation === 'issuer') invalid.set('iss', 'https://untrusted.example');
    else if (mutation === 'state') invalid.set('state', 'wrong-state');
    else invalid.append('code', 'another-code');
    const before = f.requests.length;
    const rejected = await s.callback(invalid);
    assert.equal(rejected.status, 400);
    assert.equal(rejected.headers.has('set-cookie'), false);
    assert.equal(f.requests.length, before);
    assert.equal((await s.callback()).status, 200);
    assert.equal(s.signedIn.length, 1);
  });
});

test('policy acceptance never replaces signed-token handle or UserInfo subject binding', async (t) => {
  for (const returnedHandle of ['Other@agents.example', 'scout@agents.example']) await t.test(returnedHandle, async (child) => {
    const f = await fixture(child);
    const s = await f.start();
    f.setClaims({ email: returnedHandle, email_verified: true });
    const rejected = await s.callback();
    assert.equal(rejected.status, 400);
    assert.match(await rejected.text(), /handle_binding_failed/);
    assert.equal(s.signedIn.length, 0);
  });
  await t.test('UserInfo subject', async (child) => {
    const f = await fixture(child);
    const s = await f.start();
    assert.equal((await s.callback()).status, 200);
    f.setUserInfo({ sub: 'another-agent' });
    await assert.rejects(s.party.recheck(s.signedIn[0]!), rejectsWith('userinfo_failed'));
  });
});

test('a sign-in without the email scope retains its pre-bound handle for later policy checks', async (t) => {
  const f = await fixture(t);
  const s = await f.start(f.rp({ scopes: ['openid'] }));
  f.setClaims({});
  assert.equal((await s.callback()).status, 200);
  const signIn = s.signedIn[0]!;
  assert.equal(signIn.claims.email, undefined, 'the SDK must not invent an email claim');
  assert.equal(s.party.liveCheckOf(signIn).handle, handle);
  assert.deepEqual(await s.party.recheck(signIn), { sub: 'fixture-agent' });
  f.remove();
  await assert.rejects(s.party.recheck(s.party.liveCheckOf(signIn)), rejectsWith('issuer_not_accepted'));
});

test('policy configuration rejects an unrestricted federation, Relay, non-URL default client or shared secret', async (t) => {
  const f = await fixture(t);
  for (const override of [
    { federation: 'any' as const }, { issuers: [{ issuer: f.issuer, relay: true }] },
    { clientId: 'registered-default' }, { clientId: 'http://rp.example/client.json' },
    { issuers: [f.issuer], clientSecret: 'shared-secret' },
  ]) assert.throws(() => f.rp(override));
  assert.deepEqual(f.requests, []);
});

test('applications that do not opt in retain their explicit issuer and no-handle sign-in behavior', async (t) => {
  const f = await fixture(t);
  const rp = f.rp({ issuerPolicy: undefined, issuers: [f.issuer], clientId: 'registered-legacy' });
  f.remove();
  const begun = await rp.begin();
  const jwt = await f.sign(begun.pending.nonce, {}, 'registered-legacy');
  const claims = await rp.validateIdToken(jwt, { issuer: f.issuer, clientId: 'registered-legacy', nonce: begun.pending.nonce });
  assert.equal(claims.sub, 'fixture-agent');
  assert.equal(f.policyFetches(), 0);
  assert.equal(begun.pending.loginHint, undefined);
});
