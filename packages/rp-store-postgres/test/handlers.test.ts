import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { test, type TestContext } from 'node:test';
import { serve } from '@hono/node-server';
import { AgentLogin, MemoryCookieJar, MemoryKeystore } from '../../agentlogin/src/index.js';
import { createIssuer } from '../../issuer/src/index.js';
import {
  createHandlers, RelyingParty, RelyingPartyError,
  type CallbackStateStore, type SignIn,
} from '../../rp/src/index.js';
import { fixture, skipPostgres } from './helpers.js';

async function listeningServer(t: TestContext, fetch: (request: Request) => Response | Promise<Response>) {
  const server = serve({ fetch, hostname: '127.0.0.1', port: 0 });
  t.after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      if ('closeAllConnections' in server) server.closeAllConnections();
    });
  });
  if (!server.listening) await once(server, 'listening');
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

test('PostgreSQL callbacks across RP instances exchange once and preserve the real Issuer session', { skip: skipPostgres }, async (t) => {
  const { store, peer } = await fixture(t, { realClock: true });
  let dispatch: (request: Request) => Response | Promise<Response> = () => new Response('starting', { status: 503 });
  const issuer = await listeningServer(t, (request) => dispatch(request));
  const { app } = await createIssuer({
    issuer, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin',
  });
  let tokenRequests = 0;
  dispatch = (request) => {
    if (new URL(request.url).pathname === '/token') tokenRequests += 1;
    return app.fetch(request);
  };
  let metadata: (request: Request) => Response = () => new Response('starting', { status: 503 });
  const rpOrigin = await listeningServer(t, (request) => new URL(request.url).pathname === '/client-metadata.json'
    ? metadata(request) : new Response('not found', { status: 404 }));
  const options = {
    clientId: `${rpOrigin}/client-metadata.json`, redirectUri: `${rpOrigin}/callback`, issuers: [issuer],
    staticIssuers: { 'example.com': issuer }, stateSecret: 'postgres-callback-integration-secret'.repeat(2),
    allowInsecure: true,
  };
  const firstRp = new RelyingParty(options);
  const secondRp = new RelyingParty(options);
  let completed: SignIn | undefined;
  let signIns = 0;
  const handlersFor = (rp: RelyingParty, callbackStore: CallbackStateStore) => createHandlers(rp, {
    callbackStore, metadata: { clientName: 'PostgreSQL callback integration', maxSignupsPerOwner: 2 },
    onSignIn: (signIn) => { signIns += 1; completed = signIn; return new Response('signed in'); },
    log: () => {},
  });
  const first = handlersFor(firstRp, store);
  const second = handlersFor(secondRp, peer);
  metadata = first.metadata;
  const admin = async (path: string, body: unknown) => {
    const response = await fetch(`${issuer}${path}`, {
      method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.ok(response.ok);
    return response.json() as Promise<Record<string, string>>;
  };
  const owner = await admin('/admin/owners', { email: 'owner@example.com', name: 'Owner' });
  await admin('/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id, name: 'Scout' });
  const started = await first.login(new Request(`${rpOrigin}/login?handle=scout%40example.com`));
  assert.equal(started.status, 302);
  const cookie = started.headers.get('set-cookie')!.split(';')[0]!;
  const agent = new AgentLogin({
    handle: 'scout@example.com', issuer, allowInsecure: true, keystore: new MemoryKeystore(), cookies: new MemoryCookieJar(),
  });
  await agent.enroll({ credential: owner.credential! });
  const result = await agent.signIn({ authorizationUrl: started.headers.get('location')!, expectedHost: new URL(rpOrigin).host });
  const callback = () => new Request(result.redirectUrl, { headers: { cookie } });
  const responses = await Promise.all([first.callback(callback()), second.callback(callback())]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 400]);
  assert.match(await responses.find((response) => response.status === 400)!.text(), /duplicate_callback/);
  assert.equal(signIns, 1);
  assert.equal(tokenRequests, 1);
  assert.ok(completed);
  await firstRp.recheck(completed);

  for (const handlers of [first, second]) {
    const replay = await handlers.callback(callback());
    assert.equal(replay.status, 400);
    assert.match(await replay.text(), /duplicate_callback/);
  }
  assert.equal(signIns, 1);
  assert.equal(tokenRequests, 1, 'no replay reaches the Token Endpoint with the legitimate PKCE proof');
  await secondRp.recheck(completed); // A proved code replay would revoke this Access Token at the real Issuer.
});

// The remaining tests isolate the handler/storage boundary. They keep the production preflight and error
// handling, while replacing successful token exchange with an instrumented operation for deterministic faults.
const testIssuer = 'https://issuer.example';
const redirectUri = 'https://rp.example/callback?view=one&view=two';
type Counters = { exchanges: number; signIns: number; uncertainExchange?: boolean };

class InstrumentedRelyingParty extends RelyingParty {
  constructor(private readonly counts: Counters) {
    super({
      clientId: 'postgres-handler-tests', redirectUri, issuers: [testIssuer],
      stateSecret: 'postgres-handler-contract-secret'.repeat(2),
    });
  }

  override async begin() {
    const state = randomBytes(24).toString('base64url');
    return {
      url: `${testIssuer}/authorize?state=${state}`,
      pending: { state, issuer: testIssuer, nonce: 'nonce', verifier: 'verifier' },
    };
  }

  override async complete(parameters: Parameters<RelyingParty['complete']>[0]): Promise<SignIn> {
    const checked = this.preflightCallback(parameters);
    if (checked.error) return super.complete(parameters);
    this.counts.exchanges += 1;
    if (this.counts.uncertainExchange) {
      throw new RelyingPartyError('token_request_failed', 'exchange acknowledgement lost', undefined, {
        cause: new Error('connection closed after exchange'),
      });
    }
    return {
      agent: { iss: testIssuer, sub: 'agent', key: `${testIssuer} agent`, scopes: ['openid'] },
      claims: {}, issuer: testIssuer, accessToken: 'token', accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 600,
    };
  }
}

function handlersFor(store: CallbackStateStore, counts: Counters, applicationFailure?: Error) {
  return createHandlers(new InstrumentedRelyingParty(counts), {
    callbackStore: store, log: () => {},
    onSignIn: () => {
      counts.signIns += 1;
      if (applicationFailure) throw applicationFailure;
      return new Response('signed in');
    },
  });
}

async function start(handlers: ReturnType<typeof createHandlers>) {
  const response = await handlers.login(new Request('https://rp.example/login'));
  assert.equal(response.status, 302);
  const state = new URL(response.headers.get('location')!).searchParams.get('state')!;
  const cookie = response.headers.get('set-cookie')!.split(';')[0]!;
  return {
    params: () => new URLSearchParams({ state, iss: testIssuer, code: 'code' }),
    request: (params = new URLSearchParams({ state, iss: testIssuer, code: 'code' })) =>
      new Request(`${redirectUri}&${params}`, { headers: { cookie } }),
  };
}

test('PostgreSQL handler contract: failed and uncertain claims fail closed before exchange', { skip: skipPostgres }, async (t) => {
  for (const phase of ['before-commit', 'after-commit'] as const) {
    await t.test(phase, async (t) => {
      const { store, peer } = await fixture(t, {
        realClock: true,
        onCheckpoint: (event) => {
          if (event.operation === 'claim' && event.phase === phase) throw new Error('injected claim acknowledgement failure');
        },
      });
      const counts: Counters = { exchanges: 0, signIns: 0 };
      const first = handlersFor(store, counts);
      const second = handlersFor(peer, counts);
      const flow = await start(first);
      const failed = await first.callback(flow.request());
      assert.equal(failed.status, 500);
      assert.match(await failed.text(), /state_store_failed/);
      assert.equal(counts.exchanges, 0);
      assert.equal(counts.signIns, 0);
      const retry = await second.callback(flow.request());
      if (phase === 'after-commit') {
        assert.equal(retry.status, 400);
        assert.match(await retry.text(), /duplicate_callback/);
        assert.equal(counts.exchanges, 0, 'an unacknowledged durable claim cannot authorize another caller');
      } else {
        assert.equal(retry.status, 200, 'a confirmed rollback left no claim and no exchange');
        assert.equal(counts.exchanges, 1);
      }
    });
  }
});

test('PostgreSQL handler contract: application failure and uncertain exchange never release state', { skip: skipPostgres }, async (t) => {
  for (const failure of ['application', 'exchange'] as const) {
    await t.test(failure, async (t) => {
      const { store, peer } = await fixture(t, { realClock: true });
      const counts: Counters = { exchanges: 0, signIns: 0, uncertainExchange: failure === 'exchange' };
      const applicationFailure = new Error('application session storage failed');
      const first = handlersFor(store, counts, failure === 'application' ? applicationFailure : undefined);
      const second = handlersFor(peer, counts);
      const flow = await start(first);
      if (failure === 'application') {
        await assert.rejects(first.callback(flow.request()), (error) => error === applicationFailure);
      } else {
        const response = await first.callback(flow.request());
        assert.equal(response.status, 502);
        assert.match(await response.text(), /token_request_failed/);
      }
      counts.uncertainExchange = false;
      const replay = await second.callback(flow.request());
      assert.equal(replay.status, 400);
      assert.match(await replay.text(), /duplicate_callback/);
      assert.equal(counts.exchanges, 1);
      assert.equal(counts.signIns, failure === 'application' ? 1 : 0);
    });
  }
});

test('PostgreSQL handler contract: valid Issuer errors consume state without an exchange', { skip: skipPostgres }, async (t) => {
  const { store, peer } = await fixture(t, { realClock: true });
  const counts: Counters = { exchanges: 0, signIns: 0 };
  const first = handlersFor(store, counts);
  const second = handlersFor(peer, counts);
  const flow = await start(first);
  const params = flow.params();
  params.delete('code');
  params.set('error', 'access_denied');
  params.set('error_description', 'owner_declined');
  const denied = await first.callback(flow.request(params));
  assert.equal(denied.status, 400);
  assert.match(await denied.text(), /owner declined/);
  assert.match(denied.headers.get('set-cookie')!, /Max-Age=0/);
  const replay = await second.callback(flow.request());
  assert.equal(replay.status, 400);
  assert.match(await replay.text(), /duplicate_callback/);
  assert.equal(counts.exchanges, 0);
  assert.equal(counts.signIns, 0);
});

test('PostgreSQL handler contract: malformed Issuer responses preserve state for another instance', { skip: skipPostgres }, async (t) => {
  const { store, peer } = await fixture(t, { realClock: true });
  const counts: Counters = { exchanges: 0, signIns: 0 };
  const first = handlersFor(store, counts);
  const second = handlersFor(peer, counts);
  const cases: Array<[string, (params: URLSearchParams) => void]> = [
    ['missing issuer', (params) => params.delete('iss')],
    ['wrong issuer', (params) => params.set('iss', 'https://other.example')],
    ['duplicate issuer', (params) => params.append('iss', testIssuer)],
    ['duplicate state', (params) => params.append('state', params.get('state')!)],
    ['code and error', (params) => params.set('error', 'access_denied')],
    ['empty code', (params) => params.set('code', '')],
    ['success with error details', (params) => params.set('error_description', 'denied')],
  ];
  for (const [name, mutate] of cases) await t.test(name, async () => {
    const flow = await start(first);
    const params = flow.params();
    mutate(params);
    const before = { ...counts };
    const rejected = await first.callback(flow.request(params));
    assert.equal(rejected.status, 400);
    assert.equal(rejected.headers.has('set-cookie'), false);
    assert.deepEqual(counts, before);
    const legitimate = await second.callback(flow.request());
    assert.equal(legitimate.status, 200);
    assert.equal(counts.exchanges, before.exchanges + 1);
    assert.equal(counts.signIns, before.signIns + 1);
  });
});
