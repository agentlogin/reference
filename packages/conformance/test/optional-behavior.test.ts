// Exercise the harness against alternative protocol behavior, rather than its validators in isolation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { runConformance } from '../src/index.js';

type Mode = 'single-use' | 'single-use-rotated-url' | 'completed-next-fields' | 'repeatable' | 'malformed' | 'missing-terminal-state' |
  'duplicate-state' | 'duplicate-iss' | 'duplicate-error' | 'duplicate-error_description' | 'duplicate-error_uri';

async function alternativeIssuer(mode: Mode) {
  const placeholder = http.createServer();
  await new Promise<void>((resolve) => placeholder.listen(0, '127.0.0.1', resolve));
  const port = (placeholder.address() as AddressInfo).port;
  await new Promise<void>((resolve) => placeholder.close(() => resolve()));
  const issuer = `http://127.0.0.1:${port}`;
  const { app } = await createIssuer({ issuer, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const registrations = new Map<string, string[]>();
  const consumedErrors = new Map<string, string>();
  const rotatedContinues = new Map<string, string>();
  const redeemed = new Map<string, string>();
  const observed = { loopbackRefusals: 0, repeatedErrors: 0, completedNextFields: 0, replays: 0 };
  const json = (body: unknown, status: number, extra: Record<string, string> = {}) => Response.json(body, {
    status, headers: { 'cache-control': 'no-store', pragma: 'no-cache', ...extra },
  });
  let tokenQueue = Promise.resolve();
  const handle = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === '/authorize') {
      const redirect = url.searchParams.get('redirect_uri') ?? '';
      const registered = registrations.get(url.searchParams.get('client_id') ?? '');
      // This issuer chooses exact matching for every registered URI, including loopback ports.
      if (registered && /^http:\/\/(127\.0\.0\.1|\[::1\]):\d+\/cb$/.test(redirect) && !registered.includes(redirect)) {
        observed.loopbackRefusals += 1;
        return json({ error: 'invalid_request' }, 400, mode === 'malformed' ? { location: redirect } : {});
      }
    }
    const previousError = consumedErrors.get(request.url);
    if (previousError) {
      observed.repeatedErrors += 1;
      if (mode === 'malformed') return json({ redirect: `${previousError}&code=unexpected` }, 200);
      if (mode === 'missing-terminal-state') return json({ error: 'transaction_expired' }, 410);
      if (mode.startsWith('duplicate-')) {
        const redirect = new URL(previousError);
        const name = mode.slice('duplicate-'.length);
        if (!redirect.searchParams.has(name)) redirect.searchParams.set(name, 'original');
        redirect.searchParams.append(name, 'conflicting');
        return json({ redirect: redirect.href }, 200);
      }
      if (mode === 'repeatable') {
        const redirect = new URL(previousError);
        redirect.search = new URLSearchParams([...redirect.searchParams].reverse()).toString();
        return json({ redirect: redirect.href }, 200);
      }
      if (mode === 'single-use-rotated-url') {
        const nextUrl = `${request.url}/rotated`;
        rotatedContinues.set(nextUrl, previousError);
        return json({ error: 'transaction_expired', status: 'denied', next: { action: 'continue', method: 'GET', url: nextUrl } }, 410);
      }
      return json({ error: 'transaction_expired', status: 'denied', next: { action: 'continue', method: 'GET', url: request.url } }, 410);
    }
    const rotatedError = rotatedContinues.get(request.url);
    if (rotatedError) {
      rotatedContinues.delete(request.url);
      consumedErrors.set(request.url, rotatedError);
      return json({ redirect: rotatedError }, 200);
    }
    if (url.pathname === '/token') {
      // Serialize redemption, enforcing single use but choosing not to revoke the first token on replay.
      const predecessor = tokenQueue;
      let release!: () => void;
      tokenQueue = new Promise<void>((resolve) => { release = resolve; });
      await predecessor;
      try {
        const body = await request.clone().text();
        const proof = `${request.headers.get('authorization') ?? ''}\n${body}`;
        const code = new URLSearchParams(body).get('code') ?? '';
        if (redeemed.get(code) === proof) {
          observed.replays += 1;
          return json({ error: 'invalid_grant' }, 400);
        }
        const response = await app.fetch(request);
        if (response.status === 200) redeemed.set(code, proof);
        return response;
      } finally { release(); }
    }
    const response = await app.fetch(request);
    if (mode === 'completed-next-fields' && url.pathname.includes('/continue/') && response.status === 410) {
      const body = await response.clone().json() as { status?: string; next?: { action?: string } };
      if (body.status === 'completed' && body.next?.action === 'none') {
        observed.completedNextFields += 1;
        // These optional members describe no action and are never followed by the harness.
        return json({ ...body, next: { ...body.next, method: 'GET', url: request.url } }, 410);
      }
    }
    if (url.pathname === '/register' && response.status === 201) {
      const registration = await response.clone().json() as { client_id: string; redirect_uris: string[] };
      registrations.set(registration.client_id, registration.redirect_uris);
    }
    if (url.pathname.includes('/continue/') && response.status === 200) {
      const body = await response.clone().json() as { redirect?: string };
      if (body.redirect && new URL(body.redirect).searchParams.has('error')) consumedErrors.set(request.url, body.redirect);
    }
    return response;
  };
  const server = serve({ fetch: handle, port, hostname: '127.0.0.1' });
  return { issuer, observed, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

for (const mode of ['single-use', 'single-use-rotated-url', 'completed-next-fields', 'repeatable'] as const) test(`optional behavior stays optional with ${mode} continuations`, async () => {
  const fixture = await alternativeIssuer(mode);
  try {
    const report = await runConformance({ issuer: fixture.issuer, adminToken: 'admin' });
    assert.equal(report.failed, 0, report.results.filter((r) => r.outcome === 'fail').map((r) => `${r.id}: ${r.detail}`).join('\n'));
    assert.ok(fixture.observed.loopbackRefusals >= 2, 'the harness actually tried different IPv4 and IPv6 ports');
    assert.ok(fixture.observed.repeatedErrors > 0, 'the harness actually repeated a denied continuation');
    if (mode === 'completed-next-fields') assert.ok(fixture.observed.completedNextFields > 0, 'the harness actually received optional next members after completion');
    assert.ok(fixture.observed.replays > 0, 'the harness actually replayed a successful redemption');
    assert.equal(report.results.find((r) => r.id === 'I-17')?.outcome, 'pass');
    assert.equal(report.results.find((r) => r.id === 'I-40')?.outcome, 'pass');
    const advisory = report.results.find((r) => r.id === 'I-19' && r.title.includes('(SHOULD,'));
    assert.equal(advisory?.outcome, 'skip');
    assert.match(advisory?.detail ?? '', /recommendation.*was not followed/);
  } finally { await fixture.close(); }
});

test('optional behavior still fails for an unsafe redirect refusal or changed repeated error response', async () => {
  const fixture = await alternativeIssuer('malformed');
  try {
    const report = await runConformance({ issuer: fixture.issuer, adminToken: 'admin' });
    assert.equal(report.results.find((r) => r.id === 'I-17')?.outcome, 'fail');
    assert.equal(report.results.find((r) => r.id === 'I-40')?.outcome, 'fail');
    assert.match(report.results.find((r) => r.id === 'I-17')?.detail ?? '', /optional repeated denied continue/);
    assert.match(report.results.find((r) => r.id === 'I-40')?.detail ?? '', /optional loopback port variation/);
  } finally { await fixture.close(); }
});

for (const mode of ['missing-terminal-state', 'duplicate-state', 'duplicate-iss', 'duplicate-error', 'duplicate-error_description', 'duplicate-error_uri'] as const) {
  test(`I-17 rejects ${mode} on a repeated denied continuation`, async () => {
    const fixture = await alternativeIssuer(mode);
    try {
      const report = await runConformance({ issuer: fixture.issuer, adminToken: 'admin' });
      assert.ok(fixture.observed.repeatedErrors > 0, 'the malformed response was exercised');
      const result = report.results.find((r) => r.id === 'I-17');
      assert.equal(result?.outcome, 'fail');
      assert.match(result?.detail ?? '', /optional repeated denied continue/);
    } finally { await fixture.close(); }
  });
}
