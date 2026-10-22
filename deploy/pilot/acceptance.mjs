#!/usr/bin/env node
// Public smoke and live pilot acceptance. No bootstrap/admin API, shell credential or raw HTTP logging.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { AgentLogin, FileKeystore, MemoryCookieJar } from 'agentlogin';

export function origin(value) {
  const url = new URL(value);
  assert.ok(url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/', 'Expected an HTTPS origin');
  return url.origin;
}

export async function readJson(response, expectedStatus) {
  assert.equal(response.status, expectedStatus, 'Unexpected HTTP status');
  assert.match(response.headers.get('content-type') ?? '', /^application\/json(?:;|$)/i, 'Expected JSON');
  const reader = response.body?.getReader();
  assert.ok(reader, 'Expected a response body');
  const chunks = []; let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      assert.ok(bytes <= 64 * 1024, 'Response exceeded the pilot limit');
      chunks.push(part.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

export async function smoke(base, request = fetch) {
  const get = (path) => request(base + path, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
  const health = await get('/healthz');
  assert.match(health.headers.get('cache-control') ?? '', /no-store/);
  assert.equal((await readJson(health, 200)).status, 'alive');
  assert.equal((await readJson(await get('/readyz'), 200)).status, 'ready');
  const metadata = await readJson(await get('/client-metadata.json'), 200);
  assert.equal(metadata.client_id, base + '/client-metadata.json');
  assert.deepEqual(metadata.redirect_uris, [base + '/auth/agent/callback']);
  assert.equal(metadata.initiate_login_uri, base + '/auth/agent/login');
  assert.equal(metadata.client_name, 'Agent Workspace');
  const unauthenticated = await get('/me');
  assert.match(unauthenticated.headers.get('cache-control') ?? '', /no-store/);
  assert.equal(unauthenticated.headers.get('access-control-allow-origin'), null);
  await readJson(unauthenticated, 401);
  return { publicSmoke: true };
}

/** Verify durable logout separately from clearing the current client's cookie jar. */
export async function logoutAndVerify(base, cookies, request, replay = fetch) {
  const retiredCookie = await cookies.header(new URL(base + '/me'));
  assert.ok(retiredCookie, 'Expected an authenticated application cookie before logout');
  assert.equal((await readJson(await request('/logout', 'POST'), 200)).signed_out, true);
  await readJson(await request('/me'), 401);
  // A cookie deletion alone is not logout. Keep the old value only in memory and deliberately replay it.
  await readJson(await replay(base + '/me', {
    headers: { cookie: retiredCookie }, redirect: 'error', signal: AbortSignal.timeout(10_000),
  }), 401);
}

export async function lifecycle({ base, issuer, handle, keyFile, waitForRevocation, report = () => {} }) {
  const cookies = new MemoryCookieJar();
  const agent = new AgentLogin({ handle, issuer, keystore: new FileKeystore(keyFile), cookies, timeoutMs: 10_000, maxFollowBodyBytes: 64 * 1024 });
  const request = (path, method = 'GET', body) => agent.fetch(base + path, {
    method, signal: AbortSignal.timeout(10_000),
    ...(body ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}),
  });
  const signIn = async () => {
    const result = await agent.signInAt(base + '/auth/agent/login', {
      acceptDisclosure: false,
      deadlineMs: 300_000,
      onReview: (tx) => tx.client.client_id === base + '/client-metadata.json'
        && tx.client.redirect_host === new URL(base).host
        && tx.requested_scopes.every((scope) => ['openid', 'email', 'profile'].includes(scope)) ? 'allow' : 'deny',
      onOwnerApproval: () => report({ awaitingOwnerApproval: true }),
    });
    assert.equal(result.issuer, issuer);
    assert.equal(result.client.client_id, base + '/client-metadata.json');
    const followed = await agent.follow(result);
    assert.equal(followed.status, 200, 'Application callback failed');
    const me = await readJson(await request('/me'), 200);
    assert.equal(me.iss, issuer);
    assert.equal(me.handle, handle);
    assert.ok(typeof me.sub === 'string' && me.sub.length > 0);
    return me;
  };
  let finalLogout = false;
  try {
    const first = await signIn();
    const note = { id: randomUUID(), text: 'Agent Workspace pilot acceptance ' + new Date().toISOString() };
    assert.equal((await readJson(await request('/notes', 'POST', note), 200)).saved, true);
    // Retrying an acknowledged action must not create another note.
    assert.equal((await readJson(await request('/notes', 'POST', note), 200)).saved, true);
    const notes = (await readJson(await request('/notes'), 200)).notes;
    assert.equal(notes.filter((item) => item.id === note.id && item.text === note.text).length, 1);
    await logoutAndVerify(base, cookies, request);
    const second = await signIn();
    assert.equal(second.sub, first.sub);
    assert.equal(second.first_seen, first.first_seen);
    assert.ok((await readJson(await request('/notes'), 200)).notes.some((item) => item.id === note.id));
    let revokedActionDenied = false;
    if (waitForRevocation) {
      report({ awaitingOwnerRevocation: true });
      await waitForRevocation();
      const response = await readJson(await request('/notes', 'POST', { ...note, id: randomUUID() }), 401);
      assert.equal(response.error, 'revoked');
      revokedActionDenied = true;
    }
    await logoutAndVerify(base, cookies, request);
    finalLogout = true;
    return { authenticated: true, actionPersisted: true, actionIdempotent: true, logout: true, signInAgain: true, finalLogout, revokedActionDenied, crossHostEvidence: false };
  } finally {
    // Best effort only: an unavailable service cannot promise logout. The ephemeral jar is never persisted.
    if (!finalLogout) try { await (await request('/logout', 'POST')).body?.cancel(); } catch { /* report no additional success */ }
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has('--help')) {
    console.log('Usage: PILOT_BASE_URL=https://workspace.example node deploy/pilot/acceptance.mjs [--authenticated --accept-disclosure] [--revocation]\nAuthenticated mode also needs PILOT_ISSUER, PILOT_HANDLE and PILOT_KEY_FILE. It signs in with an existing enrolled key, accepts only openid/email/profile for this exact app, writes one private test note, logs out and signs in again. --revocation pauses for the human Owner to revoke the dedicated test Agent. No secrets or personal claims are printed.');
    return;
  }
  assert.ok([...args].every((arg) => ['--authenticated', '--accept-disclosure', '--revocation'].includes(arg)), 'Unknown argument');
  assert.ok(!args.has('--revocation') || args.has('--authenticated'), '--revocation requires --authenticated');
  const base = origin(process.env.PILOT_BASE_URL);
  const result = await smoke(base);
  if (args.has('--authenticated')) {
    assert.ok(args.has('--accept-disclosure'), 'Authenticated mode requires --accept-disclosure');
    assert.ok(process.env.PILOT_HANDLE && process.env.PILOT_KEY_FILE, 'PILOT_HANDLE and PILOT_KEY_FILE are required');
    const issuer = origin(process.env.PILOT_ISSUER);
    const waitForRevocation = args.has('--revocation') ? async () => {
      assert.ok(process.stdin.isTTY, '--revocation needs an interactive terminal');
      const terminal = createInterface({ input: process.stdin, output: process.stderr });
      try { assert.equal(await terminal.question('Revoke the dedicated test Agent in the Owner dashboard, then type revoked: '), 'revoked', 'Revocation was not confirmed'); }
      finally { terminal.close(); }
    } : undefined;
    Object.assign(result, await lifecycle({ base, issuer, handle: process.env.PILOT_HANDLE, keyFile: process.env.PILOT_KEY_FILE, waitForRevocation, report: (value) => console.error(JSON.stringify(value)) }));
  }
  console.log(JSON.stringify(result));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error(JSON.stringify({ accepted: false, error: 'Pilot acceptance failed; inspect service health and the configured test account without logging credentials.' })); process.exitCode = 1; });
}
