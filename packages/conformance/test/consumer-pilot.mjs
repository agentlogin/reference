// Copied unchanged into a fresh consumer directory. Imports only installed package entry points.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { serve } from '@hono/node-server';
import { Pool } from 'pg';
import { createIssuer } from '@agentlogin/issuer';
import { PostgresStore } from '@agentlogin/store-postgres';
import { PostgresCallbackStateStore } from '@agentlogin/rp-store-postgres';
import { AgentLogin, FileKeystore, FileCookieJar } from 'agentlogin';
import { LoginRuntime } from '@agentlogin/mcp';
import { resolve } from 'node:path';
import { createExample } from 'agentlogin-example-rp-hono';
import { PostgresSessionStore } from 'agentlogin-example-rp-hono/postgres-session-store';

const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
assert.ok(connectionString);
const schema = 'consumer_' + randomUUID().replaceAll('-', '');
const schemaNames = [schema, schema + '_cb', schema + '_app'];
const admin = new Pool({ connectionString, max: 2 });
const servers = [], stores = [];
async function listen(getHandler) {
  const server = serve({ hostname: '127.0.0.1', port: 0, fetch: (request) => getHandler()(request) });
  servers.push(server);
  if (!server.listening) await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}
try {
  let issuerApp, application;
  const issuer = await listen(() => (request) => issuerApp.fetch(request));
  const base = await listen(() => (request) => application.fetch(request));
  const authority = new PostgresStore({ connectionString, schema }); stores.push(authority);
  await authority.migrate();
  const callbacks = new PostgresCallbackStateStore({ connectionString, schema: schemaNames[1] }); stores.push(callbacks);
  await callbacks.migrate();
  const sessionConfig = { connectionString, schema: schemaNames[2], namespace: base, sessionSecret: randomUUID().repeat(2) };
  const sessions = new PostgresSessionStore(sessionConfig); stores.push(sessions); await sessions.migrate();
  // Bootstrap is a test fixture only. Production Owner authentication is exercised by the hosted-service suite.
  const adminToken = randomUUID();
  const built = await createIssuer({ issuer, store: authority, handleDomains: ['example.com'], allowInsecureClients: true, adminToken });
  issuerApp = built.app;
  const options = { base, issuer, stateSecret: randomUUID().repeat(2), callbackStore: callbacks, handleDomains: ['example.com'] };
  application = createExample({ ...options, sessionStore: sessions }).app;
  async function bootstrap(path, body) {
    const response = await fetch(issuer + path, { method: 'POST', headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal(response.ok, true, path); return response.json();
  }
  const owner = await bootstrap('/admin/owners', { name: 'Pilot owner', email: 'pilot-owner@example.com' });
  await bootstrap('/admin/agents', { handle: 'pilot@example.com', name: 'Pilot', owner_id: owner.owner_id });
  const agent = new AgentLogin({ handle: 'pilot@example.com', issuer, allowInsecure: true, keystore: new FileKeystore('./private/keys.json'), cookies: new FileCookieJar('./private/cookies.json') });
  await agent.enroll({ credential: owner.credential });
  await agent.follow(await agent.signInAt(base + '/auth/agent/login'));
  const first = await agent.fetch(base + '/me'); assert.equal(first.status, 200);
  const identity = await first.json();
  const note = { id: randomUUID(), text: 'Installed independently; persists across application instances.' };
  const save = await agent.fetch(base + '/notes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(note) });
  assert.equal(save.status, 200);
  const secondHost = new PostgresSessionStore(sessionConfig); stores.push(secondHost);
  application = createExample({ ...options, sessionStore: secondHost }).app;
  assert.deepEqual(await (await agent.fetch(base + '/me')).json(), identity);
  assert.equal((await (await agent.fetch(base + '/notes')).json()).notes[0].text, note.text);
  assert.equal((await agent.fetch(base + '/logout', { method: 'POST' })).status, 200);
  application = createExample({ ...options, sessionStore: sessions }).app;
  assert.equal((await agent.fetch(base + '/me')).status, 401);
  await agent.follow(await agent.signInAt(base + '/auth/agent/login'));
  assert.equal((await (await agent.fetch(base + '/notes')).json()).notes.length, 1);
  // The installed helper uses its own private jar, the real SDK and this application's immutable identity probe.
  const helper = new LoginRuntime({ version: 1, stateDirectory: resolve('private'), developmentLoopback: true,
    identities: { pilot: { handle: 'pilot@example.com', issuer } },
    applications: { notes: { name: 'Agent Workspace', origin: base, loginPath: '/auth/agent/login',
      sessionCheck: { path: '/me', handlePointer: '/handle', issuerPointer: '/iss', subjectPointer: '/sub' }, logoutPath: '/logout',
      operations: {
        list: { description: 'Read notes', method: 'GET', path: '/notes', queryFields: ['before'], output: { notes: '/notes', next_cursor: '/next_cursor' } },
        save: { description: 'Save a note', method: 'POST', path: '/notes', inputFields: ['id', 'text'], output: { saved: '/saved' } },
      } } },
  });
  const operation = helper.start('pilot', 'notes').operation;
  const helperDeadline = Date.now() + 30_000;
  for (;;) {
    const progress = helper.status(operation);
    if (progress.status === 'awaiting_consent') helper.review(operation, 'allow'); // Explicit fixture disclosure acceptance.
    if (progress.status === 'authenticated') break;
    assert.notEqual(progress.status, 'failed', JSON.stringify(progress));
    assert.ok(Date.now() < helperDeadline, 'helper sign-in exceeded the pilot deadline');
    await new Promise((done) => setTimeout(done, 10));
  }
  assert.equal((await helper.request('pilot', 'notes', 'list')).succeeded, true);
  assert.equal((await helper.request('pilot', 'notes', 'save', { id: randomUUID(), text: 'Saved through the installed local helper.' })).succeeded, true);
  assert.equal((await helper.logout('pilot', 'notes')).loggedOut, true);
  await assert.rejects(helper.request('pilot', 'notes', 'list'));
  const stored = await authority.getAgent('pilot@example.com');
  assert.ok(stored);
  await authority.setAgentEnabled('pilot@example.com', false, stored.sub, await authority.currentTime(0));
  assert.equal((await agent.fetch(base + '/notes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...note, id: randomUUID() }) })).status, 401);
  console.log(JSON.stringify({ installedPackages: true, postgres: true, signIn: true, persistedAction: true, crossInstance: true, logout: true, helperSession: true, revokedActionDenied: true }));
} finally {
  await Promise.all(servers.map((server) => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); })));
  await Promise.all(stores.map((store) => store.close()));
  try { for (const name of schemaNames) await admin.query(`DROP SCHEMA IF EXISTS "${name}" CASCADE`); }
  finally { await admin.end(); }
}
