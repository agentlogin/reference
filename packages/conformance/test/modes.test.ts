// The harness's operating modes against a persistent issuer: repeated admin-mode runs, and an existing Agent without
// an admin token (reported against commit 9b6dd09: the first crashed with 409, the second before any report).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { runConformance } from '../src/index.js';

let issuerUrl = '';
let rpUrl = '';
const closers: Array<() => Promise<void>> = [];
const admin = async (path: string, body: unknown) =>
  (await (await fetch(`${issuerUrl}${path}`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()) as Record<string, string>;

before(async () => {
  const probe = http.createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as AddressInfo).port;
  await new Promise<void>((r) => probe.close(() => r()));
  issuerUrl = `http://127.0.0.1:${port}`;
  const { app } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' });
  closers.push(() => new Promise((r) => server.close(() => r())));
  const rp = http.createServer((req, res) => {
    if (req.url === '/client-metadata.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ client_id: `${rpUrl}/client-metadata.json`, redirect_uris: [`${rpUrl}/cb`], token_endpoint_auth_method: 'none', client_name: 'Open test client' }));
    } else { res.writeHead(404); res.end(); }
  });
  await new Promise<void>((r) => rp.listen(0, '127.0.0.1', r));
  rpUrl = `http://127.0.0.1:${(rp.address() as AddressInfo).port}`;
  closers.push(() => new Promise((r) => rp.close(() => r())));
  await new Promise((r) => setTimeout(r, 50));
});
after(async () => { for (const c of closers) await c(); });

const failures = (r: Awaited<ReturnType<typeof runConformance>>) => r.results.filter((x) => x.outcome === 'fail').map((x) => `${x.id}: ${x.detail}`).join('\n');

test('admin mode can be run repeatedly against the same issuer', async () => {
  const first = await runConformance({ issuer: issuerUrl, adminToken: 'admin' });
  assert.equal(first.failed, 0, failures(first));
  const second = await runConformance({ issuer: issuerUrl, adminToken: 'admin' });
  assert.equal(second.failed, 0, failures(second));
  assert.ok(second.passed >= 30, `passed ${second.passed}`);
});

test('existing-agent mode without an admin token produces a report', async () => {
  const owner = await admin('/admin/owners', { email: 'existing@example.org', name: 'Existing Owner', session_auth: 'passkey' });
  await admin('/admin/agents', { handle: 'existing@example.com', owner_id: owner.owner_id!, name: 'Existing' });
  const base = { issuer: issuerUrl, handle: 'existing@example.com', ownerCredential: owner.credential! };
  // with an Open Client as the only client
  const open = await runConformance({ ...base, openClient: { clientId: `${rpUrl}/client-metadata.json`, redirectUri: `${rpUrl}/cb` } });
  assert.equal(open.failed, 0, failures(open));
  assert.ok(open.passed >= 10, `passed ${open.passed}`);
  assert.ok(open.skipped > 0, 'checks that need the bootstrap API are skipped, not failed');
  // with a Registered Client fixture
  const reg = (await (await fetch(`${issuerUrl}/register`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['https://fixture.example/cb'], client_name: 'Fixture', tos_uri: 'https://fixture.example/tos', policy_uri: 'https://fixture.example/privacy', token_endpoint_auth_method: 'client_secret_basic' }) })).json()) as Record<string, string>;
  const registered = await runConformance({ ...base, client: { clientId: reg.client_id!, clientSecret: reg.client_secret!, redirectUri: 'https://fixture.example/cb' } });
  assert.equal(registered.failed, 0, failures(registered));
  assert.ok(registered.passed >= 15, `passed ${registered.passed}`);
  // and a second run with the same fixtures
  const again = await runConformance({ ...base, client: { clientId: reg.client_id!, clientSecret: reg.client_secret!, redirectUri: 'https://fixture.example/cb' } });
  assert.equal(again.failed, 0, failures(again));
});

test('a run that cannot work says why instead of crashing', async () => {
  await assert.rejects(runConformance({ issuer: issuerUrl }), /admin token, or an existing handle/);
  await assert.rejects(runConformance({ issuer: issuerUrl, handle: 'existing@example.com', ownerCredential: 'x' }), /needs a client|enroll/);
});
