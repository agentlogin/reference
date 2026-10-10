// The command line, run as a subprocess against the reference issuer and an application built with @agentlogin/rp.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { RelyingParty, createHandlers, type SignIn } from '../../rp/src/index.js';

const BIN = fileURLToPath(new URL('../bin/agentlogin.js', import.meta.url));
let issuerUrl = '';
let appUrl = '';
let credential = '';
const home = mkdtempSync(join(tmpdir(), 'agentlogin-cli-'));
const closers: Array<() => Promise<void>> = [];

async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}
function cli(args: string[], env: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH ?? '', AGENTLOGIN_HOME: home, AGENTLOGIN_INSECURE: '1', AGENTLOGIN_ISSUER: issuerUrl, AGENTLOGIN_HANDLE: 'scout@example.com', ...env } }, (err, stdout, stderr) =>
      resolve({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout, stderr }),
    );
  });
}

before(async () => {
  const ip = await freePort();
  issuerUrl = `http://127.0.0.1:${ip}`;
  const { app } = await createIssuer({ issuer: issuerUrl, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const is = serve({ fetch: app.fetch, port: ip, hostname: '127.0.0.1' });
  closers.push(() => new Promise((r) => is.close(() => r())));
  const ap = await freePort();
  appUrl = `http://127.0.0.1:${ap}`;
  const rp = new RelyingParty({ clientId: `${appUrl}/client-metadata.json`, redirectUri: `${appUrl}/auth/agent/callback`, issuers: [issuerUrl], staticIssuers: { 'example.com': issuerUrl }, stateSecret: 'cli-test-secret-cli-test-secret-123456', allowInsecure: true });
  const sessions = new Map<string, SignIn>();
  const h = createHandlers(rp, {
    metadata: { clientName: 'CLI Test App' },
    onSignIn: (s) => { const sid = `s${sessions.size + 1}x${Math.floor(performance.now())}`; sessions.set(sid, s); return new Response(null, { status: 302, headers: { location: '/me', 'set-cookie': `sid=${sid}; Path=/; HttpOnly` } }); },
  });
  const as = serve({
    port: ap,
    hostname: '127.0.0.1',
    fetch: (req: Request) => {
      const u = new URL(req.url);
      const s = sessions.get(/(?:^|;\s*)sid=([^;]+)/.exec(req.headers.get('cookie') ?? '')?.[1] ?? '');
      if (u.pathname === '/client-metadata.json') return h.metadata(req);
      if (u.pathname === '/auth/agent/login') return h.login(req);
      if (u.pathname === '/auth/agent/callback') return h.callback(req);
      if (u.pathname === '/me') return s ? Response.json({ handle: s.agent.handle }) : Response.json({ error: 'not signed in' }, { status: 401 });
      return new Response('not found', { status: 404 });
    },
  });
  closers.push(() => new Promise((r) => as.close(() => r())));
  await new Promise((r) => setTimeout(r, 50));
  const post = async (path: string, body: unknown) => (await (await fetch(`${issuerUrl}${path}`, { method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()) as Record<string, string>;
  const owner = await post('/admin/owners', { email: 'jane@example.com' });
  credential = owner.credential!;
  await post('/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id!, name: 'Scout' });
  await post('/admin/agents', { handle: 'rover@example.com', owner_id: owner.owner_id!, name: 'Rover' });
});
after(async () => { for (const c of closers) await c(); });

test('usage errors exit 2 and name the problem', async () => {
  const unknown = await cli(['frobnicate']);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /unknown command frobnicate/);
  const flag = await cli(['whoami', '--nope']);
  assert.equal(flag.code, 2);
  const missing = await cli(['login', '--json']);
  assert.equal(missing.code, 2);
  assert.equal(JSON.parse(missing.stdout).error.code, 'usage');
  // a boolean flag does not swallow the positional that follows it
  const order = await cli(['login', '--json', `${appUrl}/auth/agent/login`]);
  assert.equal(JSON.parse(order.stdout).error.code, 'no_key');
  assert.equal(order.code, 1);
  assert.equal((await cli(['--help'])).code, 0);
  const argv = await cli(['enroll', '--credential', 'secret-on-argv']);
  assert.equal(argv.code, 2);
  assert.match(argv.stderr, /not accepted on the command line/);
  assert.equal((await cli(['login', `${appUrl}/auth/agent/login`, '--timeout', 'soon'])).code, 2);
});

test('enroll, login, fetch, cookies and revoke', async () => {
  const file = join(home, 'credential');
  writeFileSync(file, `${credential}\n`, { mode: 0o600 });
  const enroll = await cli(['enroll', '--credential-file', file, '--json']);
  assert.equal(enroll.code, 0, enroll.stderr);
  const kid = JSON.parse(enroll.stdout).kid as string;
  assert.equal(JSON.parse(enroll.stdout).status, 'active');
  assert.equal(statSync(join(home, 'keys.json')).mode & 0o777, 0o600);

  const login = await cli(['login', `${appUrl}/auth/agent/login`, '--json']);
  assert.equal(login.code, 0, login.stderr + login.stdout);
  const summary = JSON.parse(login.stdout);
  assert.equal(summary.signed_in, true);
  assert.equal(summary.site, new URL(appUrl).host);
  assert.equal(summary.site_status, 200);
  for (const leak of ['code=', 'state=', credential]) assert.equal((login.stdout + login.stderr).includes(leak), false, `output contains ${leak}`);

  const me = await cli(['fetch', `${appUrl}/me`]);
  assert.equal(me.code, 0);
  assert.equal(JSON.parse(me.stdout).handle, 'scout@example.com');

  // cookies are per Agent and their values are not printed
  const jar = readdirSync(join(home, 'cookies')).filter((f) => f.endsWith('.json'));
  assert.equal(jar.length, 1);
  assert.match(jar[0]!, /^[0-9a-f]{64}\.json$/, 'the jar is named by a hash of the handle');
  const sid = (JSON.parse(readFileSync(join(home, 'cookies', jar[0]!), 'utf8')) as Array<{ name: string; value: string }>).find((c) => c.name === 'sid')!.value;
  const cookies = await cli(['cookies', '--site', appUrl]);
  assert.match(cookies.stdout, /sid/);
  assert.equal(cookies.stdout.includes(sid), false);
  for (const handle of ['rover@example.com', 'Scout@example.com']) { // the local part is case-sensitive: Scout is another Agent
    const other = await cli(['fetch', `${appUrl}/me`], { AGENTLOGIN_HANDLE: handle });
    assert.equal(other.code, 1, `${handle} has no session at the application`);
    assert.match(other.stderr, /401/);
  }

  // the wrong application is refused before any assertion
  const wrong = await cli(['login', `${appUrl}/auth/agent/login`, '--site', 'other.example', '--json']);
  assert.equal(wrong.code, 1);
  assert.equal(JSON.parse(wrong.stdout).error.code, 'unexpected_client');

  // the callback may live on another host that the caller names explicitly
  const accept = await cli(['login', `${appUrl}/auth/agent/login`, '--site', 'app.example', '--accept-host', new URL(appUrl).host, '--json']);
  assert.equal(JSON.parse(accept.stdout).signed_in, true, accept.stdout);

  // --no-follow reports that no session was created
  const nofollow = await cli(['login', `${appUrl}/auth/agent/login`, '--no-follow', '--json']);
  assert.equal(JSON.parse(nofollow.stdout).signed_in, false);

  const revoke = await cli(['revoke', '--kid', kid], { AGENTLOGIN_CREDENTIAL: credential });
  assert.equal(revoke.code, 0, revoke.stderr);
  const after = await cli(['login', `${appUrl}/auth/agent/login`, '--json']);
  assert.equal(after.code, 1);
  assert.equal(JSON.parse(after.stdout).error.code, 'no_key');
  const cleared = await cli(['cookies', '--site', appUrl, '--clear']);
  assert.equal(cleared.code, 0);
  assert.equal((await cli(['fetch', `${appUrl}/me`])).code, 1);
});
