// Starts the reference issuer on a loopback port and runs the black-box conformance harness against it.
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createIssuer, type Store } from '../src/index.js';
import { runConformance } from '../../conformance/src/index.js';

async function listen(handler: http.RequestListener): Promise<{ url: string; port: number; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, port, close: () => new Promise((r) => server.close(() => r())) };
}
/** Serves `handler` as http://localhost:{port} on both loopback addresses, whichever `localhost` resolves to first. */
async function listenLocalhost(handler: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  const v4 = await listen(handler);
  const v6 = http.createServer(handler);
  const bound = await new Promise<boolean>((r) => v6.once('error', () => r(false)).listen(v4.port, '::1', () => r(true)));
  return { url: `http://localhost:${v4.port}`, close: async () => { await v4.close(); if (bound) await new Promise<void>((r) => v6.close(() => r())); } };
}
const json = (res: http.ServerResponse, body: unknown) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

export async function conformanceRun(store?: Store): Promise<void> {
  // Open Client metadata documents hosted by the test (Section 4.2); dev mode permits loopback http. Besides the valid
  // one, documents the issuer must refuse at step 1 of Section 5.2.
  const refused: Record<string, Record<string, unknown>> = {
    '/rs256.json': { id_token_signed_response_alg: 'RS256' },
    '/no-redirect-uris.json': { redirect_uris: undefined },
    '/bad-cap.json': { max_signups_per_owner: -1 },
    '/bad-review.json': { require_review: 'yes' },
    '/secret.json': { token_endpoint_auth_method: 'client_secret_basic' },
  };
  const rp = await listen((req, res) => {
    const doc = { client_id: `${rp.url}${req.url}`, redirect_uris: [`${rp.url}/cb`], token_endpoint_auth_method: 'none', client_name: 'Open test client' };
    if (req.url === '/client-metadata.json') return json(res, doc);
    if (req.url && refused[req.url]) return json(res, { ...doc, ...refused[req.url] });
    res.writeHead(404);
    res.end();
  });
  // A Relay's metadata (Sections 2.4, 4.4), under a host name so that look-alike hosts can be formed.
  const relay = await listenLocalhost((req, res) => {
    if (req.url === '/.well-known/openid-configuration') return json(res, { issuer: relay.url, op_policy_uri: `${relay.url}/policy`, home_issuers: ['*'], handle_domains: [] });
    res.writeHead(404);
    res.end();
  });

  const placeholder = await listen(() => {});
  const port = placeholder.port;
  await placeholder.close();
  const issuerUrl = `http://127.0.0.1:${port}`;
  // The mailbox of the Owner email sign-in (Section 7.5): the issuer delivers its one-time codes here.
  const mailbox = new Map<string, string>();
  const { app, ctx } = await createIssuer({
    issuer: issuerUrl,
    handleDomains: ['example.com', '*.agents.example'],
    allowInsecureClients: true,
    adminToken: 'test-admin',
    store,
    sendOwnerCode: ({ email, code }) => { mailbox.set(email, code); },
  });
  const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' });
  await new Promise((r) => setTimeout(r, 50));
  const post = (path: string, body: unknown) => fetch(`${issuerUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const lines: string[] = [];
    const report = await runConformance({
      issuer: issuerUrl,
      adminToken: ctx.adminToken,
      openClient: { clientId: `${rp.url}/client-metadata.json`, redirectUri: `${rp.url}/cb` },
      invalidOpenClients: Object.keys(refused).map((path) => ({ name: path.slice(1, -5), clientId: `${rp.url}${path}`, redirectUri: `${rp.url}/cb` })),
      relayIssuer: relay.url,
      // The issuer's own one-time-code sign-in: ask for a code, read it from the mailbox, exchange it for an Owner Credential.
      ownerEmailSignIn: async (email) => {
        assert.equal((await post('/owner/sessions/email', { email })).status, 202);
        const code = mailbox.get(email);
        assert.ok(code, `no one-time code was delivered to ${email}`);
        const verified = await post('/owner/sessions/email/verify', { email, code });
        assert.equal(verified.status, 200);
        const reused = await post('/owner/sessions/email/verify', { email, code });
        assert.equal(reused.status, 401, 'a one-time code works once');
        return ((await verified.json()) as { credential: string }).credential;
      },
      log: (l) => lines.push(l),
    });
    for (const r of report.results) if (r.outcome !== 'pass') console.log(`${r.outcome.toUpperCase()} ${r.id} ${r.title}: ${r.detail ?? ''}`);
    assert.equal(report.failed, 0, `failed checks: ${report.results.filter((r) => r.outcome === 'fail').map((r) => `${r.id}: ${r.detail}`).join('\n')}`);
    const entropy = report.results.filter((r) => r.id === 'I-9' && r.title === 'Entropy generation for identifiers, challenges, tokens and continue URLs');
    assert.equal(entropy.length, 1, 'the report identifies the entropy evidence gap once');
    assert.equal(entropy[0]!.outcome, 'skip', 'black-box checks cannot prove random generation');
    assert.equal(report.results.find((r) => r.id === 'I-9' && r.title.startsWith('Identifier and token encodings'))?.outcome, 'pass');
    assert.equal(report.results.filter((r) => r.outcome === 'skip' && !r.title.includes('(SHOULD,') && r !== entropy[0]).length, 0,
      'all automated mandatory probes ran; only unobservable entropy and unavailable advisory evidence may be skipped');
    assert.ok(report.passed >= 20, `only ${report.passed} checks passed`);
    for (let i = 38; i <= 49; i += 1) assert.equal(report.results.find((r) => r.id === `I-${i}`)?.outcome, 'pass', `I-${i}`);
    assert.equal(report.results.find((r) => r.id === 'I-56')?.outcome, 'pass', 'registration authentication method requirements were exercised');
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await rp.close();
    await relay.close();
  }
}
