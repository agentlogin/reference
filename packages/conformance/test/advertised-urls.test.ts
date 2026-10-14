// Full harness runs against issuers whose advertised routes differ from the reference issuer's layout.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { runConformance } from '../src/index.js';

type Mode = 'query-secret' | 'assertion-route' | 'rotating-url' | 'credential-leak' | 'unsafe-release' | 'repeatable-ready';

async function alternativeIssuer(mode: Mode) {
  const placeholder = http.createServer();
  await new Promise<void>((resolve) => placeholder.listen(0, '127.0.0.1', resolve));
  const port = (placeholder.address() as AddressInfo).port;
  await new Promise<void>((resolve) => placeholder.close(() => resolve()));
  const issuer = `http://127.0.0.1:${port}`;
  const { app } = await createIssuer({ issuer, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const observed = { queryRequests: 0, terminalAssertions: 0, rotatedRequests: 0, leaks: 0, unsafeReleases: 0, repeatedCodes: 0 };
  const completed = new Map<string, unknown>();
  const advertised = new Map<string, string>();
  const firstVersion = new Map<string, string>();
  let version = 0;
  let inI43 = false;
  const log = (line: string) => {
    if (/^(PASS|FAIL|SKIP) I-42\b/.test(line)) inI43 = true;
    if (/^(PASS|FAIL|SKIP) I-43\b/.test(line)) inI43 = false;
  };
  const externalize = (value: unknown): unknown => {
    if (typeof value === 'string' && value.startsWith(`${issuer}/transactions/`)) {
      const url = new URL(value);
      const match = /^(.*\/continue)\/([^/]+)$/.exec(url.pathname);
      if (mode === 'query-secret' && match) {
        url.pathname = match[1]!;
        url.searchParams.set('ticket', match[2]!);
        return url.href;
      }
      if (mode === 'rotating-url' && match) {
        url.searchParams.set('version', String(++version));
        advertised.set(url.href, value);
        if (!firstVersion.has(value)) firstVersion.set(value, url.href);
        return url.href;
      }
      if (mode === 'assertion-route' && url.pathname.endsWith('/assertion')) {
        url.pathname = url.pathname.slice(0, -'/assertion'.length) + '/prove';
        return url.href;
      }
    }
    if (Array.isArray(value)) return value.map(externalize);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, externalize(item)]));
    return value;
  };
  const json = (body: unknown, status: number) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
  const handle = async (original: Request): Promise<Response> => {
    let request = original;
    const url = new URL(request.url);
    if (mode === 'query-secret' && url.pathname.endsWith('/continue') && url.searchParams.has('ticket')) {
      observed.queryRequests += 1;
      url.pathname += `/${url.searchParams.get('ticket')}`;
      url.searchParams.delete('ticket');
      request = new Request(url, request);
    }
    if (mode === 'assertion-route' && url.pathname.startsWith('/transactions/')) {
      if (url.pathname.endsWith('/assertion')) return json({ error: 'invalid_transaction' }, 404);
      if (url.pathname.endsWith('/prove')) {
        url.pathname = url.pathname.slice(0, -'/prove'.length) + '/assertion';
        request = new Request(url, request);
      }
    }
    if (mode === 'rotating-url' && url.pathname.includes('/continue/')) {
      const canonical = advertised.get(request.url);
      if (!canonical) return json({ error: 'invalid_transaction' }, 404);
      if (inI43 && firstVersion.get(canonical) !== request.url) observed.rotatedRequests += 1;
      request = new Request(canonical, request);
    }
    if (mode === 'repeatable-ready' && completed.has(request.url)) {
      if (inI43) observed.repeatedCodes += 1;
      return json(completed.get(request.url), 200);
    }
    const response = await app.fetch(request);
    if (!response.headers.get('content-type')?.includes('application/json')) return response;
    const body = await response.json() as Record<string, any>;
    if (mode === 'assertion-route' && original.url.endsWith('/prove') && response.status === 410 && body.status === 'completed') observed.terminalAssertions += 1;
    if (mode === 'credential-leak' && request.method === 'GET' && !request.headers.has('authorization') && body.status === 'ready') {
      observed.leaks += 1;
      body.transaction_token = 'leaked-credential';
    }
    if (mode === 'unsafe-release' && inI43 && response.status >= 400 && body.next?.url) {
      observed.unsafeReleases += 1;
      body.next.url = 'https://attacker.invalid/continue';
    }
    if (mode === 'repeatable-ready' && url.pathname.includes('/continue/') && response.status === 200 && typeof body.redirect === 'string' && new URL(body.redirect).searchParams.has('code')) completed.set(request.url, body);
    return new Response(JSON.stringify(externalize(body)), { status: response.status, headers: response.headers });
  };
  const server = serve({ fetch: handle, port, hostname: '127.0.0.1' });
  return { issuer, observed, log, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

for (const mode of ['query-secret', 'assertion-route', 'rotating-url'] as const) test(`harness follows advertised URLs with ${mode}`, async () => {
  const fixture = await alternativeIssuer(mode);
  try {
    const report = await runConformance({ issuer: fixture.issuer, adminToken: 'admin', log: fixture.log });
    assert.equal(report.failed, 0, report.results.filter((r) => r.outcome === 'fail').map((r) => `${r.id}: ${r.detail}`).join('\n'));
    assert.equal(report.results.find((r) => r.id === 'I-9' && r.title.includes('encodings'))?.outcome, 'pass');
    const entropy = report.results.find((r) => r.id === 'I-9' && r.title.startsWith('Entropy generation'));
    assert.equal(entropy?.outcome, 'skip');
    assert.match(entropy?.detail ?? '', /encoding length does not establish entropy/);
    assert.equal(report.results.find((r) => r.id === 'I-37')?.outcome, 'pass');
    assert.equal(report.results.find((r) => r.id === 'I-43')?.outcome, 'pass');
    if (mode === 'query-secret') assert.ok(fixture.observed.queryRequests > 0, 'continue URLs actually carried their secret in a query');
    if (mode === 'assertion-route') assert.ok(fixture.observed.terminalAssertions > 0, 'the terminal assertion used the advertised route');
    if (mode === 'rotating-url') assert.ok(fixture.observed.rotatedRequests >= 8, 'I-43 followed and reused the updated URL for all four transactions');
  } finally { await fixture.close(); }
});

for (const [mode, id, detail] of [
  ['credential-leak', 'I-9', /reveals a credential/],
  ['unsafe-release', 'I-43', /valid next.url/],
  ['repeatable-ready', 'I-43', /reuse of the released continue URL/],
] as const) test(`advertised URL flexibility still detects ${mode}`, async () => {
  const fixture = await alternativeIssuer(mode);
  try {
    const report = await runConformance({ issuer: fixture.issuer, adminToken: 'admin', log: fixture.log });
    const result = report.results.find((r) => r.id === id && r.outcome === 'fail');
    assert.ok(result, `expected ${id} to fail`);
    assert.match(result.detail ?? '', detail);
    if (mode === 'credential-leak') assert.ok(fixture.observed.leaks > 0);
    if (mode === 'unsafe-release') assert.ok(fixture.observed.unsafeReleases > 0);
    if (mode === 'repeatable-ready') assert.ok(fixture.observed.repeatedCodes > 0);
  } finally { await fixture.close(); }
});
