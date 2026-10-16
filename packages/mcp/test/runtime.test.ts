import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryCookieJar, AgentLoginError, type SignInAtOptions, type SignInResult, type TransactionView } from 'agentlogin';
import { LoginRuntime, readJson, safeError, type SessionBinding } from '../src/runtime.js';
import { parseConfig, readPrivateConfig } from '../src/config.js';
import { CatalogSchema, catalogView } from '../src/catalog.js';
import { acquireStateLease } from '../src/private-state.js';

export const config = {
  version: 1, stateDirectory: '/tmp/agentlogin-mcp-test-unused',
  identities: { alice: { handle: 'alice@example.com' }, bob: { handle: 'bob@example.com' } },
  applications: { notes: { name: 'Notes', origin: 'https://notes.example', loginPath: '/login', sessionCheck: { path: '/me', handlePointer: '/handle', issuerPointer: '/iss', subjectPointer: '/sub' }, logoutPath: '/logout',
    operations: {
      save: { description: 'Save a note', method: 'POST', path: '/notes', inputFields: ['id', 'text'], output: { saved: '/saved', value: '/value' } },
      list: { description: 'Read a page of notes', method: 'GET', path: '/notes?fixed=recent', queryFields: ['before'], output: { notes: '/notes', next_cursor: '/next_cursor' } },
    } } },
};
function fixture(overrides: { callback?: string; handle?: string; discoveryIssuer?: string; sessionIssuer?: string; sub?: string; response?: (url: string) => Response; signIn?: (o: SignInAtOptions) => Promise<void>; logout?: number; ownerPortal?: string; ownerApprovalPath?: string } = {}) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const jars = new Map<string, MemoryCookieJar>();
  const bindings = new Map<string, SessionBinding>();
  let starts = 0;
  const ownConfig = structuredClone(config);
  if (overrides.ownerPortal) Object.assign(ownConfig.identities.alice, { ownerPortal: overrides.ownerPortal, ownerApprovalPath: overrides.ownerApprovalPath });
  const runtime = new LoginRuntime(ownConfig, {
    sessionBindings: { async get(key) { return bindings.get(key); }, async set(key, value) { if (value) bindings.set(key, value); else bindings.delete(key); } },
    jarFactory: (id) => { const jar = new MemoryCookieJar(); jars.set(id, jar); return jar; },
    clientFactory: (identity, _app, jar) => ({
      async discover() { return { issuer: identity.issuer ?? overrides.discoveryIssuer ?? 'https://issuer.example' }; },
      async signInAt(_url, options) { starts += 1; await overrides.signIn?.(options); return { handle: identity.handle, issuer: identity.issuer ?? overrides.discoveryIssuer ?? 'https://issuer.example', client: { client_id: 'client', client_type: 'open', redirect_host: 'notes.example' }, scopes: ['openid'], redirectUrl: overrides.callback ?? 'https://notes.example/cb?code=TOP_SECRET_CODE' } as SignInResult; },
      async fetch(url, init) {
        calls.push({ url, init });
        const path = new URL(url).pathname;
        if (path === '/cb') { await jar.store(new URL(url), ['sid=PRIVATE_SESSION; Secure; Path=/']); return new Response('PRIVATE_CALLBACK_HTML', { status: 200 }); }
        if (path === '/me') return Response.json({ handle: overrides.handle ?? identity.handle, iss: overrides.sessionIssuer ?? identity.issuer ?? 'https://issuer.example', sub: overrides.sub ?? 'immutable-agent-1' });
        if (path === '/logout') return new Response(null, { status: overrides.logout ?? 204 });
        return overrides.response?.(url) ?? Response.json({ saved: true, value: { cookie: 'PRIVATE_SESSION', nested: 'PRIVATE_SESSION', access_token: 'UNKNOWN_PRIVATE_TOKEN' }, ignored: 'TOP_SECRET_CODE' });
      },
    }),
  });
  return { runtime, calls, jars, bindings, starts: () => starts };
}

test('callback credentials and HTML stay private; authenticated session is verified and reused', async () => {
  const f = fixture();
  const started = f.runtime.start('alice', 'notes');
  const finished = await f.runtime.settled(started.operation);
  assert.equal(finished.status, 'authenticated');
  assert.equal(finished.browserSession, false);
  assert.doesNotMatch(JSON.stringify([started, finished]), /TOP_SECRET|PRIVATE_|redirectUrl/);
  const response = await f.runtime.request('alice', 'notes', 'save', { id: 'idempotent_id_1234', text: 'hello' });
  assert.equal(response.succeeded, true);
  assert.doesNotMatch(JSON.stringify(response), /PRIVATE_|UNKNOWN_/);
  assert.equal(f.calls.filter((c) => new URL(c.url).pathname === '/me').length, 2);
  assert.equal(f.calls.find((c) => new URL(c.url).pathname === '/notes')?.init?.body, '{"id":"idempotent_id_1234","text":"hello"}');
  await f.runtime.logout('alice', 'notes');
  assert.deepEqual(await f.jars.get('alice')!.list(), []);
});

test('response redaction omits secret-bearing property names without renaming collisions', async () => {
  const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJl';
  const secretNames = {
    PRIVATE_SESSION: 'cookie as a key',
    prefix_PRIVATE_SESSION_suffix: 'cookie inside a key',
    [jwt]: 'JWT as a key',
    'Bearer synthetic-upstream-credential': 'bearer as a key',
  };
  const f = fixture({ response: () => Response.json({ value: {
    ...secretNames, '[redacted]': 'legitimate field', safe: 'ordinary value',
    nested: [{ ...secretNames, safe: 'PRIVATE_SESSION', access_token: 'UNKNOWN_PRIVATE_TOKEN' }],
  } }) });
  await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  const response = await f.runtime.request('alice', 'notes', 'save');
  assert.deepEqual(response.data, { value: {
    '[redacted]': 'legitimate field', safe: 'ordinary value',
    nested: [{ safe: '[redacted]', access_token: '[redacted]' }],
  } });
  assert.doesNotMatch(JSON.stringify(response), /PRIVATE_SESSION|UNKNOWN_PRIVATE_TOKEN|synthetic-upstream-credential|eyJ/);
});

test('response redaction treats prototype property names as data and redacts before truncating', async () => {
  const value = JSON.parse('{"__proto__":{"polluted":"PRIVATE_SESSION"},"constructor":{"prototype":{"polluted":"PRIVATE_SESSION"}}}');
  value.long = `${'x'.repeat(8190)}PRIVATE_SESSION`;
  const f = fixture({ response: () => Response.json({ value }) });
  await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  const response = await f.runtime.request('alice', 'notes', 'save');
  const actual = response.data!.value as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(actual), Object.prototype);
  assert.equal(Object.hasOwn(actual, '__proto__'), true);
  assert.deepEqual(actual.__proto__, { polluted: '[redacted]' });
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
  assert.doesNotMatch(JSON.stringify(response), /PRIVATE_SESSION/);
  assert.equal(actual.long, `${'x'.repeat(8190)}[r`);
});

test('same host on another scheme or port is not an allowed callback origin', async () => {
  for (const callback of ['https://notes.example:444/cb?code=secret', 'https://attacker.example/cb?code=secret']) {
    const f = fixture({ callback });
    const done = await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
    assert.equal(done.status, 'failed'); assert.equal(done.error, 'callback_rejected');
    assert.equal(f.calls.length, 0);
  }
});

test('a successful callback page is insufficient when session belongs to another identity', async () => {
  const f = fixture({ handle: 'mallory@example.com' });
  const done = await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  assert.equal(done.error, 'session_mismatch');
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', {}), /no bound session/);
  assert.equal(f.calls.filter((c) => new URL(c.url).pathname === '/notes').length, 0);
});

test('disclosure must be reviewed; duplicate starts reuse the pending job; competing writes are refused', async () => {
  let reviewReady!: () => void;
  const ready = new Promise<void>((r) => { reviewReady = r; });
  let decision: unknown;
  const f = fixture({ signIn: async (o) => {
    assert.equal(o.acceptDisclosure, false);
    const reviewing = o.onReview!({ transaction_id: 'opaque', status: 'awaiting_consent', requested_scopes: ['openid', 'email'], client: { client_id: 'https://notes.example/client.json', client_type: 'open', redirect_host: 'notes.example', client_name: 'Notes', tos_uri: 'https://notes.example/terms-b', policy_uri: 'https://notes.example/privacy-b' }, consent_reason: 'material_change', disclosure: [{ scope: 'email', title: 'Email', description: 'The app receives your email.' }] } as TransactionView);
    reviewReady(); decision = await reviewing;
  } });
  const started = f.runtime.start('alice', 'notes'); await ready;
  assert.equal(f.runtime.status(started.operation).status, 'awaiting_consent');
  assert.equal(f.runtime.status(started.operation).consentReason, 'material_change');
  assert.equal(f.runtime.status(started.operation).client?.policy_uri, 'https://notes.example/privacy-b');
  assert.equal(f.runtime.status(started.operation).client?.tos_uri, 'https://notes.example/terms-b');
  assert.equal(f.runtime.start('alice', 'notes').operation, started.operation);
  assert.equal(f.starts(), 1);
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', {}), /in progress/);
  f.runtime.review(started.operation, 'allow');
  assert.throws(() => f.runtime.review(started.operation, 'allow'), /no live disclosure/);
  assert.equal((await f.runtime.settled(started.operation)).status, 'authenticated');
  assert.equal(decision, 'allow');
});

test('requests cannot add headers, arbitrary target fields, or automatic retry after remote failure', async () => {
  const f = fixture({ response: () => new Response(null, { status: 503 }) });
  await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', { url: 'https://evil.example', authorization: 'secret' }), /does not accept/);
  const result = await f.runtime.request('alice', 'notes', 'save', { text: 'x' });
  assert.equal(result.succeeded, false);
  assert.equal(f.calls.filter((c) => new URL(c.url).pathname === '/notes').length, 1);
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', { text: 'x'.repeat(33 * 1024) }), /32 KiB/);
  assert.throws(() => f.runtime.start('constructor', 'notes'), /Choose an identity/);
});

test('configured GET queries paginate bounded notes without changing the target or request headers', async () => {
  const cursor = Buffer.from(JSON.stringify([1_800_000_000, 'note_1234567890123456'])).toString('base64url');
  const firstPage = Array.from({ length: 10 }, (_, i) => ({ id: `first_${i}`, text: 'x'.repeat(4096) }));
  const lastPage = Array.from({ length: 10 }, (_, i) => ({ id: `last_${i}`, text: 'y'.repeat(4096) }));
  const f = fixture({ response: (url) => new URL(url).searchParams.has('before')
    ? Response.json({ notes: lastPage, next_cursor: null })
    : Response.json({ notes: firstPage, next_cursor: cursor }) });
  await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  const operation = f.runtime.inventory().applications[0]!.operations.find((op) => op.name === 'list');
  assert.deepEqual(operation?.queryFields, ['before']);
  assert.deepEqual(operation?.inputFields, []);
  const first = await f.runtime.request('alice', 'notes', 'list');
  assert.deepEqual(first.data, { notes: firstPage, next_cursor: cursor });
  const second = await f.runtime.request('alice', 'notes', 'list', { before: first.data!.next_cursor });
  assert.deepEqual(second.data, { notes: lastPage, next_cursor: null });
  const injected = 'https://evil.example/escape?fixed=changed&authorization=secret#fragment\r\nX-Injected: yes';
  await f.runtime.request('alice', 'notes', 'list', { before: injected });
  const requests = f.calls.filter((call) => new URL(call.url).pathname === '/notes');
  assert.equal(requests.length, 3);
  assert.deepEqual([...new URL(requests[0]!.url).searchParams], [['fixed', 'recent']]);
  assert.deepEqual([...new URL(requests[1]!.url).searchParams], [['fixed', 'recent'], ['before', cursor]]);
  assert.deepEqual([...new URL(requests[2]!.url).searchParams], [['fixed', 'recent'], ['before', injected]]);
  for (const request of requests) {
    const url = new URL(request.url);
    assert.equal(url.origin, 'https://notes.example');
    assert.equal(url.pathname, '/notes');
    assert.equal(url.hash, '');
    assert.deepEqual(request.init, { method: 'GET' });
  }
  for (const field of ['url', 'path', 'origin', 'headers', 'authorization', 'fixed']) {
    await assert.rejects(f.runtime.request('alice', 'notes', 'list', { [field]: 'not allowed' }), /does not accept/);
  }
  for (const before of [null, true, 42, ['cursor'], { cursor: 'value' }]) {
    await assert.rejects(f.runtime.request('alice', 'notes', 'list', { before }), /must be strings/);
  }
  await assert.rejects(f.runtime.request('alice', 'notes', 'list', { before: 'x'.repeat(32 * 1024) }), /32 KiB/);
  assert.equal(f.calls.filter((call) => new URL(call.url).pathname === '/notes').length, 3);
});

test('a same-handle session at the former issuer cannot satisfy a new sign-in', async () => {
  const f = fixture({ discoveryIssuer: 'https://new-issuer.example', sessionIssuer: 'https://old-issuer.example', sub: 'old-agent' });
  const result = await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  assert.equal(result.error, 'session_mismatch');
  assert.equal(f.bindings.size, 0);
});

test('every application operation requires the persisted immutable account binding and current discovered issuer', async () => {
  const state = { discoveryIssuer: 'https://issuer.example', sub: 'agent-a' };
  const f = fixture(state);
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', {}), /no bound session/);
  await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
  state.sub = 'agent-b';
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', {}), /immutable identity/);
  state.sub = 'agent-a'; state.discoveryIssuer = 'https://replacement.example';
  await assert.rejects(f.runtime.request('alice', 'notes', 'save', {}), /no bound session/);
  assert.equal(f.calls.filter((c) => new URL(c.url).pathname === '/notes').length, 0);
});

test('Owner approval links derive only from trusted configuration and the nonsecret transaction identifier', async () => {
  let reached!: () => void, finish!: () => void;
  const ready = new Promise<void>((r) => { reached = r; });
  const pending = new Promise<void>((r) => { finish = r; });
  const f = fixture({ ownerPortal: 'https://issuer.example/identity', ownerApprovalPath: '/identity/transactions/{transaction_id}', signIn: async (o) => {
    o.onOwnerApproval!({ transaction_id: 'transaction_123456789' } as TransactionView);
    reached(); await pending;
  } });
  const started = f.runtime.start('alice', 'notes'); await ready;
  const waiting = f.runtime.status(started.operation);
  assert.equal(waiting.transactionId, 'transaction_123456789');
  assert.equal(waiting.ownerApprovalUrl, 'https://issuer.example/identity/transactions/transaction_123456789');
  finish(); await f.runtime.settled(started.operation);
});

test('failed or redirecting logout retains the session for an explicit retry', async () => {
  for (const logout of [503, 302]) {
    const f = fixture({ logout });
    await f.runtime.settled(f.runtime.start('alice', 'notes').operation);
    await assert.rejects(f.runtime.logout('alice', 'notes'), /did not confirm logout/);
    assert.equal((await f.jars.get('alice')!.list()).length, 1);
  }
});

test('response limits cancel oversized streams and do not expose HTML', async () => {
  let canceled = false;
  const response = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(50)); }, cancel() { canceled = true; } }), { headers: { 'content-type': 'application/json' } });
  await assert.rejects(readJson(response, 60), /limit/);
  assert.equal(canceled, true);
  await assert.rejects(readJson(new Response('secret')), /did not return JSON/);
});

test('upstream errors cannot leak arbitrary error messages or protocol URLs', () => {
  assert.doesNotMatch(JSON.stringify(safeError(new AgentLoginError('SECRET https://example/cb?code=PRIVATE', 'malicious_secret'))), /SECRET|PRIVATE/);
  assert.equal(safeError(new AgentLoginError('SECRET', 'key_revoked')).code, 'key_revoked');
});

test('operator config rejects insecure, escaping, unknown and secret-exposing fields', () => {
  for (const origin of ['http://notes.example', 'https://notes.example/', 'https://user:secret@notes.example']) {
    const altered = structuredClone(config); altered.applications.notes.origin = origin;
    assert.throws(() => parseConfig(altered));
  }
  const altered = structuredClone(config); altered.applications.notes.operations.save.output = { saved: '/access_token', value: '/value' };
  assert.throws(() => parseConfig(altered), /Credentials/);
  assert.throws(() => parseConfig({ ...config, secret: 'not accepted' }));
  assert.throws(() => parseConfig({ ...config, applications: { app: { ...config.applications.notes, loginPath: '//evil.example/login' } } }));
});

test('query configuration is exclusive to GET and cannot override a fixed parameter', () => {
  const withOperation = (operation: Record<string, unknown>) => ({ ...config, applications: {
    notes: { ...config.applications.notes, operations: { operation } },
  } });
  const get = config.applications.notes.operations.list;
  assert.throws(() => parseConfig(withOperation({ ...get, inputFields: ['text'] })), /do not accept a body/);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    assert.throws(() => parseConfig(withOperation({ ...get, method })), /Only GET/);
  }
  assert.throws(() => parseConfig(withOperation({ ...get, method: 'POST', queryFields: [] })), /Only GET/);
  for (const path of ['/notes?before=fixed', '/notes?%62efore=fixed']) {
    assert.throws(() => parseConfig(withOperation({ ...get, path })), /cannot replace configured query/);
  }
  assert.throws(() => parseConfig(withOperation({ ...get, queryFields: ['before', 'before'] })), /must be unique/);
});

test('config file permissions and a single-process lease protect state', () => {
  const dir = mkdtempSync(join(tmpdir(), 'al-mcp-private-'));
  try {
    const file = join(dir, 'config.json'); writeFileSync(file, JSON.stringify(config), { mode: 0o600 });
    assert.equal(readPrivateConfig(file).version, 1);
    chmodSync(file, 0o644); assert.throws(() => readPrivateConfig(file), /0600/);
    chmodSync(file, 0o600); symlinkSync(file, join(dir, 'link.json')); assert.throws(() => readPrivateConfig(join(dir, 'link.json')));
    const release = acquireStateLease(dir); assert.throws(() => acquireStateLease(dir), /already in use/); release(); acquireStateLease(dir)();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('catalog review requires dated matching-revision evidence and never implies automatic trust', () => {
  const revision = 'a'.repeat(40);
  const entry = { kind: 'provider', id: 'example', name: 'Example', operator: 'Example', homepage: 'https://example.com', issuer: 'https://issuer.example.com', handleDomains: ['example.com'], status: 'reviewed', specRevision: revision, updatedAt: '2026-10-15T00:00:00Z', evidence: [] as unknown[] };
  const catalog = { version: 1, kind: 'providers', updatedAt: '2026-10-15T00:00:00Z', entries: [entry] };
  assert.equal(CatalogSchema.safeParse(catalog).success, false);
  entry.evidence = ['domain_control', 'protocol_test'].map((kind) => ({ kind, url: 'https://example.com/evidence', observedAt: '2026-10-14T00:00:00Z', expiresAt: '2026-10-16T00:00:00Z', reviewer: 'Independent reviewer', revision }));
  const parsed = CatalogSchema.parse(catalog);
  assert.equal(catalogView([parsed], Date.parse('2026-10-15T00:00:00Z'))[0]?.effectiveStatus, 'reviewed');
  assert.equal(catalogView([parsed], Date.parse('2026-10-17T00:00:00Z'))[0]?.effectiveStatus, 'review_expired');
  assert.equal(catalogView([parsed])[0]?.automaticTrust, false);
  assert.equal(CatalogSchema.safeParse({ ...catalog, entries: [entry, entry] }).success, false);
});
