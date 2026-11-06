import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { SafeFetchOptions, SafeFetchResult } from 'agentlogin';
import { RelyingPartyError } from '../src/errors.js';
import { AGENTLOGIN_TRUSTED_PROVIDERS_URL, agentLoginTrustedProviders, TrustedProviderPolicy } from '../src/trusted-providers.js';

const START = Date.parse('2026-11-06T12:00:00Z');
const ISSUER = 'https://issuer.example';
const HANDLE = 'scout@agents.example';
const FEED_URL = 'https://policy.example/trusted-providers/v1.json';
const iso = (time: number) => new Date(time).toISOString();
const errorCode = (expected: string) => (error: unknown) => error instanceof RelyingPartyError && error.code === expected;
const feed = () => ({ version: 1, programme: 'agentlogin-trusted-providers', profile: 'agent-login-core-1.0-draft-0.2-direct-es256', status: 'active', revision: 1,
  issuedAt: iso(START), expiresAt: iso(START + 24 * 60 * 60 * 1000),
  providers: [{ issuer: ISSUER, handleDomains: ['agents.example'], specRevision: '536c5d15738f45a3c2115884a0a43cdd28b06dd3', reviewUrl: 'https://reviews.example/admission/1', reviewExpiresAt: iso(START + 30 * 24 * 60 * 60 * 1000) }] });

function fixture(initial: unknown = feed()) {
  let clock = START;
  let body = Buffer.from(JSON.stringify(initial));
  let failure: Error | undefined;
  const calls: Array<{ url: string; options: SafeFetchOptions }> = [];
  let customize: ((result: SafeFetchResult) => SafeFetchResult) | undefined;
  let gate: Promise<void> | undefined;
  const policy = new TrustedProviderPolicy({ url: FEED_URL, now: () => clock, fetch: async (url, options) => {
    calls.push({ url, options });
    const result: SafeFetchResult = { url, status: 200, headers: {}, body, redirects: [] };
    if (gate) await gate;
    if (failure) throw failure;
    return customize ? customize(result) : result;
  } });
  return { policy, calls, at: (time: number) => { clock = time; }, json: (value: unknown) => { body = Buffer.from(JSON.stringify(value)); },
    bytes: (value: Buffer) => { body = value; }, fail: (error?: Error) => { failure = error; },
    customize: (fn: (result: SafeFetchResult) => SafeFetchResult) => { customize = fn; }, waitFor: (promise: Promise<void>) => { gate = promise; } };
}

test('official factory is explicit and fixed; self-hosted policies require an operator-selected HTTPS URL', () => {
  assert.equal(AGENTLOGIN_TRUSTED_PROVIDERS_URL, 'https://agentlogin.github.io/reference/trusted-providers/v1.json');
  assert.ok(agentLoginTrustedProviders() instanceof TrustedProviderPolicy);
  for (const url of ['http://policy.example/feed', 'https://user:password@policy.example/feed', 'https://policy.example/feed#fragment', 'https://policy.example/\nfeed', 'https://policy.example\\feed']) {
    assert.throws(() => new TrustedProviderPolicy({ url }));
  }
});

test('admission is exact issuer plus exact reviewed handle domain; missing handles never load the feed', async () => {
  const f = fixture();
  for (const handle of [undefined, '', 'not-a-handle', 'scout@agents.example.']) await assert.rejects(f.policy.assertAccepted(ISSUER, handle), errorCode('issuer_not_accepted'));
  assert.equal(f.calls.length, 0);
  await f.policy.assertAccepted(ISSUER, HANDLE);
  await f.policy.assertAccepted(ISSUER, 'Scout@AGENTS.EXAMPLE');
  for (const [issuer, handle] of [[`${ISSUER}/`, HANDLE], ['https://ISSUER.example', HANDLE], [ISSUER, 'scout@sub.agents.example'], [ISSUER, 'scout@evilagents.example']]) {
    await assert.rejects(f.policy.assertAccepted(issuer, handle), errorCode('issuer_not_accepted'));
  }
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0]!.url, FEED_URL);
  assert.deepEqual(f.calls[0]!.options, { maxBytes: 65_536, timeoutMs: 10_000, maxRedirects: 0, allowPrivate: false, accept: 'application/json', headers: { 'cache-control': 'no-cache' } });
});

test('draft feeds cannot admit providers and active empty feeds grant no admission', async () => {
  const draft = { ...feed(), status: 'draft', providers: [] };
  await assert.rejects(fixture(draft).policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  await assert.rejects(fixture({ ...draft, providers: feed().providers }).policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  await assert.rejects(fixture({ ...feed(), providers: [] }).policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_not_accepted'));
  await assert.rejects(fixture({ ...feed(), providers: [{ ...feed().providers[0], status: 'candidate' }] }).policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
});

test('strict feed validation rejects catalog, protocol confusion, duplicate and noncanonical admission data', async (t) => {
  const original = feed();
  const malformed: Record<string, unknown> = {
    catalog: { version: 1, kind: 'providers', entries: [{ status: 'reviewed', issuer: ISSUER }] },
    wrongVersion: { ...original, version: 2 },
    wrongProgramme: { ...original, programme: 'agentid' },
    wrongProfile: { ...original, profile: 'agentid' },
    missingSpecificationRevision: { ...original, providers: [{ ...original.providers[0], specRevision: undefined }] },
    malformedSpecificationRevision: { ...original, providers: [{ ...original.providers[0], specRevision: 'main' }] },
    unknownField: { ...original, candidateIssuers: [ISSUER] },
    zeroRevision: { ...original, revision: 0 },
    fractionalRevision: { ...original, revision: 1.5 },
    unsafeRevision: { ...original, revision: Number.MAX_SAFE_INTEGER + 1 },
    duplicateIssuer: { ...original, providers: [original.providers[0], { ...original.providers[0], handleDomains: ['other.example'] }] },
    duplicateDomain: { ...original, providers: [original.providers[0], { ...original.providers[0], issuer: 'https://other.example' }] },
    duplicateDomainWithinEntry: { ...original, providers: [{ ...original.providers[0], handleDomains: ['agents.example', 'agents.example'] }] },
    wildcard: { ...original, providers: [{ ...original.providers[0], handleDomains: ['*.agents.example'] }] },
    uppercase: { ...original, providers: [{ ...original.providers[0], handleDomains: ['Agents.example'] }] },
    unicode: { ...original, providers: [{ ...original.providers[0], handleDomains: ['bücher.example'] }] },
    malformedALabel: { ...original, providers: [{ ...original.providers[0], handleDomains: ['xn--a.example'] }] },
    addressDomain: { ...original, providers: [{ ...original.providers[0], handleDomains: ['127.0.0.1'] }] },
    emptyDomains: { ...original, providers: [{ ...original.providers[0], handleDomains: [] }] },
    httpIssuer: { ...original, providers: [{ ...original.providers[0], issuer: 'http://issuer.example' }] },
    issuerQuery: { ...original, providers: [{ ...original.providers[0], issuer: 'https://issuer.example/?query' }] },
    credentialsInEvidence: { ...original, providers: [{ ...original.providers[0], reviewUrl: 'https://secret@reviews.example/review' }] },
    nonHttpsEvidence: { ...original, providers: [{ ...original.providers[0], reviewUrl: 'http://reviews.example/review' }] },
    relay: { ...original, providers: [{ ...original.providers[0], relay: true }] },
    otherProtocol: { ...original, providers: [{ ...original.providers[0], protocol: 'agentid' }] },
    future: { ...original, issuedAt: iso(START + 1) },
    expired: { ...original, expiresAt: iso(START) },
    excessiveLifetime: { ...original, expiresAt: iso(START + 24 * 60 * 60 * 1000 + 1) },
    impossibleDate: { ...original, issuedAt: '2026-02-30T12:00:00Z' },
    missingTimezone: { ...original, issuedAt: '2026-11-06T12:00:00' },
    malformedReviewDate: { ...original, providers: [{ ...original.providers[0], reviewExpiresAt: '2026-11-06' }] },
    tooManyProviders: { ...original, providers: Array.from({ length: 101 }, (_, i) => ({ ...original.providers[0], issuer: `https://i${i}.example`, handleDomains: [`d${i}.example`] })) },
  };
  for (const [name, value] of Object.entries(malformed)) await t.test(name, async () => {
    await assert.rejects(fixture(value).policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  });
});

test('canonical A-label domains are accepted without admitting Unicode or wildcard feed aliases', async () => {
  const f = fixture({ ...feed(), providers: [{ ...feed().providers[0], handleDomains: ['xn--bcher-kva.example'] }] });
  await f.policy.assertAccepted(ISSUER, 'scout@xn--bcher-kva.example');
  await assert.rejects(f.policy.assertAccepted(ISSUER, 'scout@bücher.example'), errorCode('issuer_not_accepted'));
});

test('cache refreshes at 60 seconds and an outage at refresh time fails closed', async () => {
  const f = fixture();
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 59_999);
  f.fail(new Error('offline'));
  await f.policy.assertAccepted(ISSUER, HANDLE);
  assert.equal(f.calls.length, 1);
  f.at(START + 60_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.at(START + 60_001);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  assert.equal(f.calls.length, 3);
  f.fail();
  await f.policy.assertAccepted(ISSUER, HANDLE);
});

test('refetching identical bytes cannot extend the original absolute expiry', async () => {
  const f = fixture({ ...feed(), expiresAt: iso(START + 90_000) });
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 60_000);
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 89_999);
  await f.policy.assertAccepted(ISSUER, HANDLE);
  assert.equal(f.calls.length, 2);
  f.at(START + 90_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  assert.equal(f.calls.length, 3);
});

test('each refresh requests origin validation; HTTP cache headers cannot extend local caching or publication expiry', async () => {
  const f = fixture({ ...feed(), expiresAt: iso(START + 90_000) });
  f.customize((response) => ({ ...response, headers: { 'cache-control': 'public, max-age=31536000', age: '0', date: new Date(START + 24 * 60 * 60 * 1000).toUTCString() } }));
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 60_000);
  await f.policy.assertAccepted(ISSUER, HANDLE);
  assert.equal(f.calls.length, 2);
  f.at(START + 90_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  assert.equal(f.calls.length, 3);
  assert.ok(f.calls.every((call) => call.options.headers?.['cache-control'] === 'no-cache'));
});

test('review expiry takes effect within a cached feed without waiting for its refresh', async () => {
  const f = fixture({ ...feed(), providers: [{ ...feed().providers[0], reviewExpiresAt: iso(START + 1_000) }] });
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 1_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_not_accepted'));
  assert.equal(f.calls.length, 1);
});

test('newer removal cannot be undone by an older revision or same-revision changed bytes', async () => {
  const f = fixture();
  await f.policy.assertAccepted(ISSUER, HANDLE);
  const removed = { ...feed(), revision: 2, providers: [] };
  f.json(removed);
  f.at(START + 60_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_not_accepted'));
  f.json(feed());
  f.at(START + 120_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.json({ ...feed(), revision: 2 });
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.bytes(Buffer.from(JSON.stringify(removed, null, 2)));
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.json({ ...feed(), revision: 3 });
  await f.policy.assertAccepted(ISSUER, HANDLE);
});

test('a newer authenticated draft does not permit falling back to an older active feed', async () => {
  const f = fixture();
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.json({ ...feed(), revision: 2, status: 'draft', providers: [] });
  f.at(START + 60_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.json(feed());
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
});

test('concurrent callers share a fetch and all observe the same refusal or failure', async () => {
  let release!: () => void;
  const f = fixture();
  f.waitFor(new Promise<void>((resolve) => { release = resolve; }));
  const pending = Array.from({ length: 20 }, () => f.policy.assertAccepted(ISSUER, HANDLE));
  assert.equal(f.calls.length, 1);
  release();
  await Promise.all(pending);
  f.at(START + 60_000);
  f.fail(new Error('offline'));
  const rejected = await Promise.allSettled(Array.from({ length: 20 }, () => f.policy.assertAccepted(ISSUER, HANDLE)));
  assert.equal(f.calls.length, 2);
  assert.ok(rejected.every((result) => result.status === 'rejected' && errorCode('issuer_policy_unavailable')(result.reason)));
});

test('expiry reached during a delayed fetch is checked after the response', async () => {
  let release!: () => void;
  const f = fixture({ ...feed(), expiresAt: iso(START + 1_000) });
  f.waitFor(new Promise<void>((resolve) => { release = resolve; }));
  const pending = f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 1_000);
  release();
  await assert.rejects(pending, errorCode('issuer_policy_unavailable'));
});

test('clock rollback cannot make a cached review or feed valid again', async () => {
  const f = fixture({ ...feed(), providers: [{ ...feed().providers[0], reviewExpiresAt: iso(START + 1_000) }] });
  await f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START + 1_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_not_accepted'));
  f.at(START + 999);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  f.at(START + 1_000);
  await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_not_accepted'));
});

test('invalid clocks and rollback while a fetch waits fail closed', async () => {
  for (const clock of [NaN, Infinity, -1, START + 0.5]) {
    const f = fixture();
    f.at(clock);
    await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
    assert.equal(f.calls.length, 0);
  }
  let release!: () => void;
  const f = fixture();
  f.waitFor(new Promise<void>((resolve) => { release = resolve; }));
  const pending = f.policy.assertAccepted(ISSUER, HANDLE);
  f.at(START - 1);
  release();
  await assert.rejects(pending, errorCode('issuer_policy_unavailable'));
});

test('non-200, redirected, malformed UTF-8, oversized and invalid JSON responses are unavailable', async () => {
  for (const customize of [
    (response: SafeFetchResult) => ({ ...response, status: 302 }),
    (response: SafeFetchResult) => ({ ...response, url: 'https://other.example/feed' }),
    (response: SafeFetchResult) => ({ ...response, redirects: [{ status: 302, headers: {} }] }),
  ]) {
    const f = fixture(); f.customize(customize);
    await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  }
  for (const bytes of [Buffer.alloc(65_537, ' '), Buffer.from([0xff, 0xfe]), Buffer.from('{'), Buffer.from('null')]) {
    const f = fixture(); f.bytes(bytes);
    await assert.rejects(f.policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
  }
});

test('the production fetch rejects a private IP publication endpoint', async () => {
  const policy = new TrustedProviderPolicy({ url: 'https://127.0.0.1/feed.json', now: () => START });
  await assert.rejects(policy.assertAccepted(ISSUER, HANDLE), errorCode('issuer_policy_unavailable'));
});
