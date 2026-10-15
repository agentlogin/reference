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

async function freePort() { const server = http.createServer(); await new Promise<void>((r) => server.listen(0, '127.0.0.1', r)); const port = (server.address() as AddressInfo).port; await new Promise<void>((r) => server.close(() => r())); return port; }
async function wait(runtime: EnrollmentRuntime) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const state = runtime.status('scout');
    if (state.status === 'active' || state.status === 'failed') return state;
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
  let ownerCredential = '';
  let creations = 0; let proofs = 0; let proofDone = false;
  const server = serve({ hostname: '127.0.0.1', port, fetch: async (request) => {
    const path = new URL(request.url).pathname;
    if (path === '/identity/enrollment-requests' && request.method === 'POST') {
      assert.equal(request.headers.get('authorization'), 'Bearer PRIVATE_MAIL_KEY');
      const body = await request.json() as any;
      assert.equal(body.public_jwk.d, undefined, 'private key never reaches the broker');
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
    ownerCredential = owner.credential;
    assert.equal((await app.request('/admin/agents', { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify({ owner_id: owner.owner_id, handle: 'scout@example.com', name: 'Scout' }) })).status, 201);
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
    const saved = JSON.parse(readFileSync(join(dir, 'enrollments', readdirSync(join(dir, 'enrollments'))[0]!), 'utf8'));
    assert.equal(saved.token, pollingToken, 'poll credential persisted only in protected helper state');
  } finally { server.closeAllConnections?.(); await new Promise<void>((r) => server.close(() => r())); rmSync(dir, { recursive: true, force: true }); }
});
