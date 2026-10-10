// Starts the reference issuer on a loopback port and runs the black-box conformance harness against it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createIssuer } from '../src/index.js';
import { runConformance } from '../../conformance/src/index.js';

async function listen(handler: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) };
}

test('reference issuer passes the conformance harness', async () => {
  // Open Client metadata document hosted by the test (Section 4.2); dev mode permits loopback http.
  let openClientId = '';
  const rp = await listen((req, res) => {
    if (req.url === '/client-metadata.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ client_id: openClientId, redirect_uris: [`${rp.url}/cb`], token_endpoint_auth_method: 'none', client_name: 'Open test client' }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  openClientId = `${rp.url}/client-metadata.json`;

  const placeholder = await listen(() => {});
  const port = Number(new URL(placeholder.url).port);
  await placeholder.close();
  const issuerUrl = `http://127.0.0.1:${port}`;
  const { app, ctx } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com', '*.agents.example'], allowInsecureClients: true, adminToken: 'test-admin' });
  const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' });
  await new Promise((r) => setTimeout(r, 50));
  try {
    const lines: string[] = [];
    const report = await runConformance({ issuer: issuerUrl, adminToken: ctx.adminToken, openClient: { clientId: openClientId, redirectUri: `${rp.url}/cb` }, log: (l) => lines.push(l) });
    for (const r of report.results) if (r.outcome !== 'pass') console.log(`${r.outcome.toUpperCase()} ${r.id} ${r.title}: ${r.detail ?? ''}`);
    assert.equal(report.failed, 0, `failed checks: ${report.results.filter((r) => r.outcome === 'fail').map((r) => `${r.id}: ${r.detail}`).join('\n')}`);
    assert.equal(report.skipped, 0);
    assert.ok(report.passed >= 20, `only ${report.passed} checks passed`);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await rp.close();
  }
});
