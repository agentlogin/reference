import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { createHandlers, RelyingParty, type CallbackStateStore } from '../src/index.js';
import { TrustedProviderPolicy, type IssuerAcceptancePolicy } from '../src/trusted-providers.js';
import { fixture, skipPostgres } from '../../rp-store-postgres/test/helpers.js';

test('PostgreSQL policy failures after a committed claim remain consumed across independent RPs', { skip: skipPostgres }, async (t) => {
  for (const failure of ['removed', 'unavailable'] as const) await t.test(failure, async (child) => {
    const handle = 'Scout@agents.example';
    const policyUrl = 'https://policy.example/trusted-providers/v1.json';
    const publishedIssuer = 'https://issuer.example';
    const redirectUri = 'https://rp.example/callback';
    const issuedAt = Date.now();
    let clock = issuedAt;
    let revision = 1;
    let mode: 'accepted' | typeof failure = 'accepted';
    let failAfterClaim = true;
    let committedClaims = 0;
    const { store, peer, admin, table } = await fixture(child, {
      realClock: true,
      onCheckpoint(event) {
        if (event.operation === 'claim' && event.phase === 'after-commit' && failAfterClaim) {
          // The feed changes only after PostgreSQL durably consumes this callback.
          failAfterClaim = false;
          committedClaims += 1;
          mode = failure;
          revision += 1;
          clock += 60_001;
        }
      },
    });

    const issuerRequests: string[] = [];
    let issuer: string;
    const server = http.createServer((request, response) => {
      issuerRequests.push(request.url!);
      response.setHeader('content-type', 'application/json');
      if (request.url === '/.well-known/openid-configuration') {
        response.end(JSON.stringify({
          issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`, userinfo_endpoint: `${issuer}/userinfo`,
          transaction_endpoint: `${issuer}/transactions`, agents_endpoint: `${issuer}/agents`,
          handle_domains: ['agents.example'], agent_key_algs_supported: ['ES256'],
          id_token_signing_alg_values_supported: ['ES256'], agent_login_versions_supported: ['1.0'],
        }));
      } else {
        // A regression that reaches the token endpoint remains visible without contacting a provider.
        response.writeHead(500);
        response.end(JSON.stringify({ error: 'unexpected_issuer_request' }));
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    child.after(() => new Promise<void>((resolve) => server.close(() => resolve())));

    const policyRequests = [0, 0];
    const policies = policyRequests.map((_, index): IssuerAcceptancePolicy => {
      const trusted = new TrustedProviderPolicy({
        url: policyUrl, now: () => clock,
        fetch: async (url, options) => {
          policyRequests[index] += 1;
          assert.equal(String(url), policyUrl);
          assert.equal(options.allowPrivate, false);
          assert.equal(options.maxRedirects, 0);
          if (mode === 'unavailable') throw new Error('fixture publisher unavailable');
          return { url: policyUrl, status: 200, headers: {}, redirects: [], body: Buffer.from(JSON.stringify({
            version: 1, programme: 'agentlogin-trusted-providers', profile: 'agent-login-core-1.0-draft-0.2-direct-es256',
            status: 'active', revision, issuedAt: new Date(issuedAt).toISOString(),
            expiresAt: new Date(issuedAt + 86_400_000).toISOString(),
            providers: mode === 'removed' ? [] : [{
              issuer: publishedIssuer, handleDomains: ['agents.example'],
              specRevision: '1234567890abcdef1234567890abcdef12345678', reviewUrl: 'https://policy.example/reviews/issuer',
              reviewExpiresAt: new Date(issuedAt + 7 * 86_400_000).toISOString(),
            }],
          })) };
        },
      });
      // Keep the real HTTPS-only policy parser and cache; only the issuer origin maps to loopback.
      return { async assertAccepted(candidate, expectedHandle) {
        assert.equal(candidate, issuer);
        await trusted.assertAccepted(publishedIssuer, expectedHandle);
      } };
    });
    let signIns = 0;
    const handlers = [store, peer].map((callbackStore: CallbackStateStore, index) => createHandlers(new RelyingParty({
      clientId: 'https://rp.example/client.json', redirectUri, issuers: [], issuerPolicy: policies[index],
      staticIssuers: { 'agents.example': issuer }, allowInsecure: true,
      stateSecret: 'postgres-trusted-policy-callback-secret'.repeat(2),
    }), { callbackStore, log: () => {}, onSignIn: () => { signIns += 1; return new Response('signed in'); } }));

    const started = await handlers[0]!.login(new Request(`https://rp.example/login?handle=${encodeURIComponent(handle)}`));
    assert.equal(started.status, 302, await started.clone().text());
    const authorization = new URL(started.headers.get('location')!);
    const cookie = started.headers.get('set-cookie')!.split(';')[0]!;
    const params = new URLSearchParams({ state: authorization.searchParams.get('state')!, iss: issuer, code: 'fixture-code' });
    const callback = () => new Request(`${redirectUri}?${params}`, { headers: { cookie } });
    assert.deepEqual((await admin.query(`SELECT used FROM ${table}`)).rows, [{ used: false }]);
    assert.deepEqual(policyRequests, [1, 0]);
    const before = issuerRequests.length;

    const rejected = await handlers[0]!.callback(callback());
    assert.equal(rejected.status, failure === 'removed' ? 400 : 503);
    assert.match(await rejected.text(), failure === 'removed' ? /issuer_not_accepted/ : /issuer_policy_unavailable/);
    assert.match(rejected.headers.get('set-cookie')!, /Max-Age=0/);
    assert.equal(committedClaims, 1);
    assert.deepEqual((await admin.query(`SELECT used FROM ${table}`)).rows, [{ used: true }]);
    assert.deepEqual(policyRequests, [2, 0], 'the callback refreshes the real policy after its durable claim');
    assert.equal(issuerRequests.length, before, 'policy failure must precede issuer requests');

    mode = 'accepted';
    revision += 1;
    clock += 60_001;
    await Promise.all(policies.map((policy) => policy.assertAccepted(issuer, handle)));
    assert.deepEqual(policyRequests, [3, 1], 'both independent policies accept the recovered publication');
    for (const handler of handlers) {
      const replay = await handler.callback(callback());
      assert.equal(replay.status, 400);
      assert.match(await replay.text(), /duplicate_callback/);
    }
    assert.deepEqual((await admin.query(`SELECT used FROM ${table}`)).rows, [{ used: true }]);
    assert.deepEqual(policyRequests, [3, 1], 'replay is refused before another policy check');
    assert.equal(issuerRequests.length, before);
    assert.equal(issuerRequests.filter((path) => path === '/token').length, 0);
    assert.equal(signIns, 0);
  });
});
