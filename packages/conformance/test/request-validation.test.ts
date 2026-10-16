// Prove the black-box probes detect permissive issuers, rather than just passing against the reference.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { runConformance } from '../src/index.js';

for (const mode of ['missing-method', 'query', 'body', 'query-and-body'] as const) {
  test(`conformance rejects an issuer accepting ${mode === 'missing-method' ? 'a missing registration method' : `unknown duplicates in ${mode}`}`, async () => {
    const placeholder = http.createServer();
    await new Promise<void>((resolve) => placeholder.listen(0, '127.0.0.1', resolve));
    const port = (placeholder.address() as AddressInfo).port;
    await new Promise<void>((resolve) => placeholder.close(() => resolve()));
    const issuer = `http://127.0.0.1:${port}`;
    const { app } = await createIssuer({ issuer, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
    let exercised = 0;
    const server = serve({ port, hostname: '127.0.0.1', fetch: async (request) => {
      const url = new URL(request.url);
      if (mode === 'missing-method' && url.pathname === '/register') {
        const body = await request.clone().json() as Record<string, unknown>;
        if (!Object.hasOwn(body, 'token_endpoint_auth_method')) {
          exercised += 1;
          request = new Request(url, { method: 'POST', headers: request.headers,
            body: JSON.stringify({ ...body, token_endpoint_auth_method: 'client_secret_basic' }) });
        }
      } else if (mode !== 'missing-method' && url.pathname === '/authorize') {
        const body = request.method === 'POST' ? new URLSearchParams(await request.clone().text()) : undefined;
        const field = 'x-conformance-extension';
        const queryCount = url.searchParams.getAll(field).length;
        const bodyCount = body?.getAll(field).length ?? 0;
        const matches = mode === 'query' ? queryCount > 1 : mode === 'body' ? bodyCount > 1 : queryCount === 1 && bodyCount === 1;
        if (matches) {
          exercised += 1;
          // Model the old behavior by allowing the request to proceed after silently ignoring the duplicates.
          url.searchParams.delete(field);
          body?.delete(field);
          request = new Request(url, { method: request.method, headers: request.headers, body: body?.toString() });
        }
      }
      return app.fetch(request);
    } });
    try {
      const report = await runConformance({ issuer, adminToken: 'admin' });
      assert.ok(exercised > 0, 'the conformance harness sent the invalid request');
      const result = report.results.find((item) => item.id === (mode === 'missing-method' ? 'I-56' : 'I-3'));
      assert.equal(result?.outcome, 'fail');
      assert.match(result?.detail ?? '', mode === 'missing-method' ? /missing method/ : new RegExp(`repeated unknown parameter in ${mode}`));
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
}
