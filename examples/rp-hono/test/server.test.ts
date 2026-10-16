import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { connectionString, fixture, quote, secret, session, sid, skipPostgres } from './helpers.js';

test('documented migration commands and PostgreSQL server persist sessions and shut down cleanly', { skip: skipPostgres }, async (t) => {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const base = `http://127.0.0.1:${(reservation.address() as AddressInfo).port}`;
  await new Promise<void>((resolve, reject) => reservation.close((e) => e ? reject(e) : resolve()));
  const f = await fixture(t, { realClock: true, namespace: base });
  const callbackSchema = `${f.schema}_cb`;
  const root = fileURLToPath(new URL('../../..', import.meta.url));
  const env = { ...process.env, RP_DATABASE_URL: connectionString!, RP_DATABASE_SCHEMA: callbackSchema, APP_DATABASE_SCHEMA: f.schema };
  // Deployment-role migrations need neither application secret; they create no sessions.
  delete env.STATE_SECRET; delete env.SESSION_SECRET;
  await f.admin.query(`DROP SCHEMA ${quote(f.schema)} CASCADE`);
  await promisify(execFile)(process.execPath, ['--import', 'tsx', 'examples/rp-hono/migrate.ts'], { cwd: root, env });
  await promisify(execFile)(process.execPath, ['--import', 'tsx', 'packages/rp-store-postgres/src/migrate.ts'], { cwd: root, env });
  const cookie = sid();
  await f.store.create(cookie, session(f.now()));
  const child = spawn(process.execPath, ['--import', 'tsx', 'examples/rp-hono/server.ts'], {
    cwd: root, env: { ...env, BASE_URL: base, STATE_SECRET: 'state-secret-distinct-for-runtime-test'.repeat(2), SESSION_SECRET: secret },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const closed = once(child, 'close');
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('example startup timed out')), 10_000);
      const done = (error?: Error) => { clearTimeout(timer); child.stdout.off('data', onData); child.off('exit', onExit); error ? reject(error) : resolve(); };
      const onData = () => { if (stdout.includes('Example application at')) done(); };
      const onExit = () => done(new Error(`example failed to start: ${stderr}`));
      child.stdout.on('data', onData); child.once('exit', onExit); onData();
    });
    assert.equal((await fetch(`${base}/client-metadata.json`)).status, 200);
    const headers = { cookie: `sid=${cookie}` };
    assert.equal((await fetch(`${base}/me`, { headers })).status, 200, 'a new server recognizes an existing shared session');
    assert.equal((await fetch(`${base}/logout`, { method: 'POST', headers })).status, 200);
    assert.equal(await f.peer.get(cookie), undefined, 'logout is durable outside the server process');
    child.kill('SIGTERM');
    const [code] = await closed;
    assert.equal(code, 0, stderr);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
    await f.admin.query(`DROP SCHEMA IF EXISTS ${quote(callbackSchema)} CASCADE`);
  }
});
