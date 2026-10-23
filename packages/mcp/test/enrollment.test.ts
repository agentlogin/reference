import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { EnrollmentRuntime } from '../src/enrollment.js';
import { parseConfig } from '../src/config.js';
import { FileKeystore } from 'agentlogin';
import { calculateJwkThumbprint, importJWK, jwtVerify } from 'jose';
import { writeState } from '../src/private-state.js';

async function freePort() { const server = http.createServer(); await new Promise<void>((r) => server.listen(0, '127.0.0.1', r)); const port = (server.address() as AddressInfo).port; await new Promise<void>((r) => server.close(() => r())); return port; }
async function wait(runtime: EnrollmentRuntime) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const state = runtime.status('scout');
    if (!state.polling && state.status !== 'not_started') return state;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('enrollment test timed out');
}

test('broker enrollment proves the local key at the actual issuer and reconciles a lost proof answer after restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentlogin-enrollment-'));
  const port = await freePort(); const origin = `http://127.0.0.1:${port}`;
  const { app } = await createIssuer({ issuer: origin, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const requestId = 'request_1234567890123456'; const pollingToken = 'PRIVATE_POLL_TOKEN_123456789';
  let enrollment: Record<string, any> | undefined;
  let ownerCredential = ''; let ownerId = ''; let webfingerRequests = 0;
  let creations = 0; let proofs = 0; let proofDone = false;
  const server = serve({ hostname: '127.0.0.1', port, fetch: async (request) => {
    const path = new URL(request.url).pathname;
    if (path === '/.well-known/webfinger') webfingerRequests += 1;
    if (path === '/identity/enrollment-requests' && request.method === 'POST') {
      assert.equal(request.headers.get('authorization'), 'Bearer PRIVATE_MAIL_KEY');
      const body = await request.json() as any;
      assert.equal(body.public_jwk.d, undefined, 'private key never reaches the broker');
      assert.equal((await app.request('/admin/agents', { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify({ owner_id: ownerId, handle: body.handle, name: 'Scout' }) })).status, 201);
      const reply = await app.request(`/agents/${encodeURIComponent(body.handle)}/keys`, { method: 'POST', headers: { authorization: `Bearer ${ownerCredential}`, 'content-type': 'application/json' }, body: JSON.stringify({ jwk: body.public_jwk, name: body.name }) });
      assert.equal(reply.status, 201); enrollment = await reply.json(); creations += 1;
      return Response.json({ request_id: requestId, polling_token: pollingToken, approval_url: `${origin}/identity/enrollment-requests/${requestId}/approve`, expires_at: Math.floor(Date.now() / 1000) + 600 }, { status: 201 });
    }
    if (path === `/identity/enrollment-requests/${requestId}`) {
      assert.equal(request.headers.get('authorization'), `Bearer ${pollingToken}`);
      return Response.json({ status: 'approved', enrollment: { ...enrollment, status: proofDone ? 'active' : 'pending' } });
    }
    const reply = await app.fetch(request);
    if (path.endsWith('/proof') && reply.status === 200) { proofs += 1; proofDone = true; return new Response('lost response', { status: 502 }); }
    return reply;
  } });
  try {
    const owner = await (await app.request('/admin/owners', { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify({ email: 'human@example.org', name: 'Human', session_auth: 'passkey' }) })).json() as any;
    ownerCredential = owner.credential; ownerId = owner.owner_id;
    assert.equal((await app.request('/.well-known/webfinger?resource=acct%3Ascout%40example.com')).status, 404, 'the identity does not exist until the broker provisions it');
    const config = parseConfig({ version: 1, stateDirectory: dir, developmentLoopback: true, identities: { scout: { handle: 'scout@example.com', issuer: origin, enrollmentEndpoint: `${origin}/identity/enrollment-requests`, enrollmentCredentialEnv: 'MAIL_KEY' } }, applications: {} });
    const first = new EnrollmentRuntime(config, { MAIL_KEY: 'PRIVATE_MAIL_KEY' });
    first.start('scout'); const uncertain = await wait(first);
    assert.equal(uncertain.status, 'failed'); assert.equal('error' in uncertain && uncertain.error, 'enrollment_uncertain');
    assert.doesNotMatch(JSON.stringify(uncertain), /PRIVATE_POLL|PRIVATE_MAIL|challenge|proof_url/);
    const stored = new FileKeystore(join(dir, 'keys.json'));
    assert.equal((await stored.list())[0]?.status, 'pending');
    const keyBefore = (await stored.list())[0]!.kid;
    const second = new EnrollmentRuntime(config, {}); second.start('scout');
    assert.equal((await wait(second)).status, 'active');
    assert.equal((await stored.list())[0]?.kid, keyBefore);
    assert.equal((await stored.list())[0]?.status, 'active');
    assert.equal(creations, 1); assert.equal(proofs, 1);
    assert.equal(webfingerRequests, 0, 'explicitly configured enrollment bootstrap uses issuer metadata before a handle exists');
    const saved = JSON.parse(readFileSync(join(dir, 'enrollments', readdirSync(join(dir, 'enrollments'))[0]!), 'utf8'));
    assert.equal(saved.token, pollingToken, 'poll credential persisted only in protected helper state');
  } finally { server.closeAllConnections?.(); await new Promise<void>((r) => server.close(() => r())); rmSync(dir, { recursive: true, force: true }); }
});


/** A provider broker with an injected decision clock; proofs are still cryptographically verified. */
async function brokerFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'agentlogin-durable-enrollment-'));
  const port = await freePort(); const origin = `http://127.0.0.1:${port}`;
  let now = Date.now();
  const requestId = 'request_durable_123456789';
  const expiresAt = Math.floor(now / 1000) + 7 * 86_400;
  const state = { status: 'pending', creations: 0, polls: 0, proofs: [] as string[], publicJwk: undefined as any,
    approvalUrl: `${origin}/identity/enrollment-requests/${requestId}/approve`, proofUrl: `${origin}/agents/scout%40example.com/keys/key/proof`,
    proofFailures: 0, reuseChallenge: false, wrongKey: false, metadataDomain: 'example.com' };
  const challenge = () => `fresh_challenge_${state.reuseChallenge ? 0 : state.proofs.length}`;
  const server = serve({ hostname: '127.0.0.1', port, fetch: async (request) => {
    const path = new URL(request.url).pathname;
    if (path === '/.well-known/openid-configuration') return Response.json({
      issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, userinfo_endpoint: `${origin}/userinfo`,
      jwks_uri: `${origin}/jwks`, transaction_endpoint: `${origin}/transactions`, agents_endpoint: `${origin}/agents`,
      handle_domains: [state.metadataDomain], agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['0.2'],
    }, { headers: { 'cache-control': 'no-store' } });
    if (path === '/identity/enrollment-requests' && request.method === 'POST') {
      assert.equal(request.headers.get('authorization'), 'Bearer PRIVATE_MAIL_KEY');
      state.creations += 1;
      const body = await request.json() as any;
      state.publicJwk = body.public_jwk;
      assert.equal(body.public_jwk.d, undefined);
      return Response.json({ request_id: requestId, polling_token: 'PRIVATE_POLL_TOKEN_123456789', approval_url: state.approvalUrl, expires_at: expiresAt }, { status: 201 });
    }
    if (path === `/identity/enrollment-requests/${requestId}`) {
      assert.equal(request.headers.get('authorization'), 'Bearer PRIVATE_POLL_TOKEN_123456789');
      state.polls += 1;
      const kid = state.wrongKey ? 'another_key' : await calculateJwkThumbprint(state.publicJwk);
      return Response.json({ status: state.status, retry_after: 5, ...(state.status === 'approved' ? { enrollment: {
        kid, status: 'pending', challenge: challenge(), proof_url: state.proofUrl, expires_at: Math.floor(now / 1000) + 86_400,
      } } : {}) });
    }
    if (path === '/agents/scout%40example.com/keys/key/proof' && request.method === 'POST') {
      assert.equal(request.headers.get('authorization'), null);
      const body = await request.json() as { proof: string };
      const { payload } = await jwtVerify(body.proof, await importJWK(state.publicJwk, 'ES256'), {
        algorithms: ['ES256'], issuer: 'scout@example.com', subject: 'scout@example.com', audience: origin, currentDate: new Date(now),
      });
      assert.equal(payload.nonce, challenge());
      state.proofs.push(String(payload.nonce));
      if (state.proofs.length <= state.proofFailures) return Response.json({ error: 'unknown_key' }, { status: 401 });
      return Response.json({ kid: await calculateJwkThumbprint(state.publicJwk), status: 'active', expires_at: Math.floor(now / 1000) + 86_400 });
    }
    return new Response(null, { status: 404 });
  } });
  const config = parseConfig({ version: 1, stateDirectory: dir, developmentLoopback: true, signInTimeoutSeconds: 10,
    identities: { scout: { handle: 'scout@example.com', issuer: origin, enrollmentEndpoint: `${origin}/identity/enrollment-requests`, enrollmentCredentialEnv: 'MAIL_KEY' } }, applications: {} });
  const options = { now: () => now, sleep: async (milliseconds: number) => { now += milliseconds; } };
  return { dir, origin, config, options, expiresAt, state,
    runtime: (withCredential = false) => new EnrollmentRuntime(config, withCredential ? { MAIL_KEY: 'PRIVATE_MAIL_KEY' } : {}, options),
    advance: (milliseconds: number) => { now += milliseconds; },
    saved: () => { const file = join(dir, 'enrollments', readdirSync(join(dir, 'enrollments'))[0]!); return { file, value: JSON.parse(readFileSync(file, 'utf8')) }; },
    close: async () => { server.closeAllConnections?.(); await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true }); },
  };
}

test('local polling pauses, restart reports the saved request without network, and approval six days later proves the same key', async () => {
  const f = await brokerFixture();
  try {
    const first = f.runtime(true); first.start('scout');
    const paused = await wait(first);
    assert.deepEqual(paused, { identity: 'scout', status: 'awaiting_owner', polling: false, resumable: true, approvalUrl: f.state.approvalUrl, expiresAt: f.expiresAt });
    assert.equal(f.state.polls, 2, 'the helper stops after its ten-second local budget instead of polling for seven days');
    const store = new FileKeystore(join(f.dir, 'keys.json'));
    const original = (await store.list())[0]!;
    f.advance(6 * 86_400_000);
    const restarted = f.runtime();
    assert.deepEqual(restarted.status('scout'), paused);
    assert.equal(f.state.polls, 2, 'status after restart is local and read-only');
    f.state.status = 'approved'; restarted.start('scout');
    const result = await wait(restarted);
    assert.equal(result.status, 'active'); assert.equal(result.resumable, false);
    assert.equal(f.state.creations, 1); assert.equal(f.state.proofs.length, 1);
    assert.equal((await store.list())[0]!.kid, original.kid);
    assert.equal((await store.list())[0]!.status, 'active');
    assert.equal(f.runtime().status('scout').status, 'active', 'completion survives another restart');
    assert.doesNotMatch(JSON.stringify([paused, result]), /PRIVATE_|privateJwk|proof_url|challenge/);
  } finally { await f.close(); }
});

test('seven-day expiry stays final across resumes and never replaces the pending key', async () => {
  const f = await brokerFixture();
  try {
    const first = f.runtime(true); first.start('scout'); await wait(first);
    const store = new FileKeystore(join(f.dir, 'keys.json'));
    const original = (await store.list())[0]!;
    f.advance(7 * 86_400_000);
    const resumed = f.runtime();
    assert.equal(resumed.status('scout').status, 'expired');
    assert.equal(resumed.start('scout').status, 'expired');
    assert.equal(resumed.status('scout').resumable, false);
    assert.equal(resumed.status('scout').approvalUrl, undefined);
    assert.equal(f.state.creations, 1); assert.equal(f.state.polls, 2);
    assert.deepEqual(await store.list(), [original]);
  } finally { await f.close(); }
});

test('denial persists and does not silently retry enrollment', async () => {
  const f = await brokerFixture();
  try {
    f.state.status = 'denied'; const first = f.runtime(true); first.start('scout');
    assert.equal((await wait(first)).status, 'denied');
    assert.equal(f.runtime().start('scout').status, 'denied');
    assert.equal(f.state.creations, 1); assert.equal(f.state.polls, 1);
  } finally { await f.close(); }
});

test('changed identity bindings stop before sending saved polling credentials or creating a replacement', async () => {
  const f = await brokerFixture();
  try {
    const first = f.runtime(true); first.start('scout'); await wait(first);
    const saved = f.saved();
    for (const change of [{ issuer: 'https://other.example' }, { handle: 'another@example.com' }, { enrollmentEndpoint: `${f.origin}/other-broker` }]) {
      const config = structuredClone(f.config); Object.assign(config.identities.scout!, change);
      const runtime = new EnrollmentRuntime(config, { MAIL_KEY: 'PRIVATE_MAIL_KEY' }, f.options);
      assert.throws(() => runtime.status('scout'), /no longer matches/);
      assert.throws(() => runtime.start('scout'), /no longer matches/);
    }
    assert.equal(readFileSync(saved.file, 'utf8'), JSON.stringify(saved.value));
    assert.equal(f.state.creations, 1); assert.equal(f.state.polls, 2);
  } finally { await f.close(); }
});

test('saved approval URLs are validated again before displaying a restart status', async () => {
  const f = await brokerFixture();
  try {
    const first = f.runtime(true); first.start('scout'); await wait(first);
    const saved = f.saved();
    for (const approvalUrl of ['https://attacker.example/approve', `${f.state.approvalUrl}?token=secret`, `${f.state.approvalUrl}#token=secret`, `${f.origin}/other/approve`]) {
      writeState(saved.file, { ...saved.value, approvalUrl });
      assert.throws(() => f.runtime().status('scout'));
    }
    assert.equal(f.state.creations, 1); assert.equal(f.state.polls, 2);
  } finally { await f.close(); }
});

test('an expired proof attempt re-polls for a new challenge, without resubmitting approval or the same nonce', async () => {
  const f = await brokerFixture();
  try {
    f.state.status = 'approved'; f.state.proofFailures = 1;
    const runtime = f.runtime(true); runtime.start('scout');
    assert.equal((await wait(runtime)).status, 'active');
    assert.deepEqual(f.state.proofs, ['fresh_challenge_0', 'fresh_challenge_1']);
    assert.equal(f.state.creations, 1);
  } finally { await f.close(); }
});

test('a broker that repeats a failed proof nonce cannot make the helper loop on it', async () => {
  const f = await brokerFixture();
  try {
    f.state.status = 'approved'; f.state.proofFailures = 2; f.state.reuseChallenge = true;
    const runtime = f.runtime(true); runtime.start('scout');
    const result = await wait(runtime);
    assert.equal(result.status, 'failed'); assert.equal(result.error, 'enrollment_uncertain'); assert.equal(result.resumable, true);
    assert.deepEqual(f.state.proofs, ['fresh_challenge_0']);
    assert.equal((await new FileKeystore(join(f.dir, 'keys.json')).list())[0]!.status, 'pending');
  } finally { await f.close(); }
});

test('enrollment bootstrap rejects issuer metadata for a different handle domain', async () => {
  const f = await brokerFixture();
  try {
    f.state.metadataDomain = 'another.example'; const runtime = f.runtime(true); runtime.start('scout');
    assert.equal((await wait(runtime)).status, 'failed');
    assert.equal(f.state.creations, 0); assert.equal(f.state.polls, 0);
    assert.deepEqual(await new FileKeystore(join(f.dir, 'keys.json')).list(), []);
  } finally { await f.close(); }
});

test('approval for another key or proof endpoint is rejected without signing', async () => {
  for (const wrongKey of [true, false]) {
    const f = await brokerFixture();
    try {
      f.state.status = 'approved'; f.state.wrongKey = wrongKey;
      if (!wrongKey) f.state.proofUrl = 'https://attacker.example/agents/proof';
      const runtime = f.runtime(true); runtime.start('scout');
      const result = await wait(runtime);
      assert.equal(result.status, 'failed');
      assert.equal(result.error, wrongKey ? 'enrollment_mismatch' : 'enrollment_response_invalid');
      assert.deepEqual(f.state.proofs, []);
    } finally { await f.close(); }
  }
});
