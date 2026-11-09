import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { SafeFetchOptions, SafeFetchResult } from 'agentlogin';
import { MemoryCallbackStateStore } from '@agentlogin/rp';
import { providerPolicyHealth } from '../policy-health.js';
import { createExample } from '../app.js';
import { MemorySessionStore } from '../session-store.js';

const start = Date.parse('2026-11-09T00:00:00Z');
const issuer = 'https://identity.example';
const handle = 'monitor@agents.example';
const hour = 3_600_000;
const iso = (value: number) => new Date(value).toISOString();
const feed = () => ({ version: 1, programme: 'agentlogin-trusted-providers', profile: 'agent-login-core-1.0-draft-0.2-direct-es256',
  status: 'active', revision: 1, issuedAt: iso(start), expiresAt: iso(start + 12 * hour),
  providers: [{ issuer, handleDomains: ['agents.example'], specRevision: 'a'.repeat(40), reviewUrl: 'https://example.test/review', reviewExpiresAt: iso(start + 7 * 24 * hour) }] });

function fixture() {
  let clock = start, document: unknown = feed(), failure = false;
  let gate: Promise<void> | undefined;
  const calls: Array<{ url: string; options: SafeFetchOptions }> = [];
  const check = providerPolicyHealth({ issuer, handle, now: () => clock, fetch: async (url, options) => {
    calls.push({ url, options });
    if (gate) await gate;
    if (failure) throw new Error('private-network-detail');
    return { url, status: 200, headers: {}, redirects: [], body: Buffer.from(JSON.stringify(document)) } as SafeFetchResult;
  } });
  return { check, calls, at: (time: number) => { clock = time; }, json: (value: unknown) => { document = value; },
    fail: (value: boolean) => { failure = value; }, wait: (value: Promise<void>) => { gate = value; } };
}

test('uses the actual consumer and fixed safe publication transport, with coalesced checks', async () => {
  const f = fixture();
  let release!: () => void;
  f.wait(new Promise<void>((resolve) => { release = resolve; }));
  const checks = Array.from({ length: 50 }, () => f.check());
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0]!.url, 'https://agentlogin.github.io/reference/trusted-providers/v1.json');
  assert.equal(f.calls[0]!.options.maxRedirects, 0);
  assert.equal(f.calls[0]!.options.allowPrivate, false);
  assert.equal(f.calls[0]!.options.maxBytes, 65_536);
  assert.equal(f.calls[0]!.options.timeoutMs, 10_000);
  release();
  assert.deepEqual(await Promise.all(checks), Array(50).fill(true));
  assert.equal(await f.check(), true);
  assert.equal(f.calls.length, 1);
});

test('warns two hours before either publication or provider review expiry, even inside a cache window', async () => {
  for (const field of ['publication', 'review']) {
    const f = fixture(), value = feed();
    if (field === 'publication') value.expiresAt = iso(start + 2 * hour + 1);
    else value.providers[0]!.reviewExpiresAt = iso(start + 2 * hour + 1);
    f.json(value);
    assert.equal(await f.check(), true);
    f.at(start + 1);
    assert.equal(await f.check(), false, field);
  }
});

test('fails for removal, invalid/currently expired feeds and malformed trust data', async () => {
  for (const value of [
    { ...feed(), providers: [] },
    { ...feed(), status: 'draft', providers: [] },
    { ...feed(), expiresAt: iso(start) },
    { ...feed(), issuedAt: iso(start + 1) },
    { ...feed(), profile: 'other-protocol' },
    { ...feed(), providers: [{ ...feed().providers[0], handleDomains: ['other.example'] }] },
  ]) {
    const f = fixture(); f.json(value); assert.equal(await f.check(), false);
  }
});

test('detects publisher stalls with absolute expiry and preserves revision rollback protection', async () => {
  const f = fixture();
  f.json({ ...feed(), revision: 2 }); assert.equal(await f.check(), true);
  f.at(start + 61_000); f.json(feed()); assert.equal(await f.check(), false);
  f.at(start + 67_000); f.json({ ...feed(), revision: 3 }); assert.equal(await f.check(), true);
  f.at(start + 10 * hour); assert.equal(await f.check(), false);
  f.at(start + 13 * hour); assert.equal(await f.check(), false);
});

test('bounds failure retries and refuses clock rollback', async () => {
  const f = fixture(); f.fail(true);
  assert.equal(await f.check(), false); assert.equal(await f.check(), false); assert.equal(f.calls.length, 1);
  f.fail(false); f.at(start + 5_000); assert.equal(await f.check(), true);
  f.at(start + 4_999); assert.equal(await f.check(), false);
});

test('optional monitor route reveals no exceptions and never replaces ordinary readiness', async () => {
  const options = { base: 'https://workspace.example', issuer, stateSecret: 'state-secret'.repeat(4), callbackStore: new MemoryCallbackStateStore(), sessionStore: new MemorySessionStore() };
  const disabled = createExample(options);
  assert.equal((await disabled.app.request('/health/provider-policy')).status, 404);
  for (const outcome of [true, false, 'exception'] as const) {
    const { app } = createExample({ ...options, providerPolicyHealth: async () => { if (outcome === 'exception') throw new Error('private-connection-value'); return outcome; } });
    const response = await app.request('/health/provider-policy');
    assert.equal(response.status, outcome === true ? 200 : 503);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('set-cookie'), null);
    assert.deepEqual(await response.json(), { status: outcome === true ? 'ready' : 'unavailable' });
    assert.equal((await app.request('/readyz')).status, 200);
    assert.equal((await app.request('/me')).status, 401);
  }
});
