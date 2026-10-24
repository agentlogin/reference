// Runs the example application. See README.md for migration, shared secrets and deployment settings.
import { serve } from '@hono/node-server';
import { SqliteCallbackStateStore } from '@agentlogin/rp';
import { PostgresCallbackStateStore } from '@agentlogin/rp-store-postgres';
import { Pool } from 'pg';
import { createExample } from './app.js';
import { MemorySessionStore, type SessionStore } from './session-store.js';
import { PostgresSessionStore } from './postgres-session-store.js';
import { listenPort, readinessCheck } from './server-config.js';

const baseUrl = new URL(process.env.BASE_URL ?? 'http://localhost:4000');
const issuer = process.env.ISSUER ?? 'http://localhost:3000'; // exactly as the Issuer publishes it
const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(baseUrl.hostname);
const dev = baseUrl.protocol === 'http:' && loopback;
if (process.env.NODE_ENV === 'production' && dev) throw new Error('Production requires an explicit HTTPS BASE_URL');
if (baseUrl.protocol !== 'https:' && !dev) throw new Error('BASE_URL must use HTTPS outside loopback development');
if (baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash || baseUrl.pathname !== '/') throw new Error('BASE_URL must be an origin URL');
const base = baseUrl.origin;
const port = listenPort(baseUrl, process.env.PORT);
if (!dev && !process.env.ISSUER) throw new Error('ISSUER is required outside loopback development');
if (!dev && !process.env.RP_DATABASE_URL) throw new Error('RP_DATABASE_URL is required outside loopback development');
if (!dev && (!process.env.STATE_SECRET || !process.env.SESSION_SECRET)) throw new Error('STATE_SECRET and SESSION_SECRET are required outside development');
const stateSecret = process.env.STATE_SECRET ?? 'development-only-state-secret-development-only';
const sessionSecret = process.env.SESSION_SECRET ?? 'development-only-session-secret-development-only';
if (stateSecret.length < 32 || sessionSecret.length < 32 || stateSecret === sessionSecret) throw new Error('STATE_SECRET and SESSION_SECRET must be distinct secrets of at least 32 characters');

// One bounded pool per process, shared by callback and application storage; every host connects to the primary.
const pool = process.env.RP_DATABASE_URL ? new Pool({
  connectionString: process.env.RP_DATABASE_URL, max: 10, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000,
}) : undefined;
pool?.on('error', () => console.error('Application database connection failed'));
let callbackStore: PostgresCallbackStateStore | SqliteCallbackStateStore | undefined;
let sessionStore: SessionStore | undefined;
let stopping = false;
const ready = readinessCheck(async () => {
  if (!pool) return;
  const client = await pool.connect(); // Pool acquisition is bounded to five seconds.
  let failed = false;
  const onError = () => { failed = true; };
  client.on('error', onError);
  const query = { text: 'SELECT 1', query_timeout: 2_000 };
  try {
    await client.query(query);
    if (failed) throw new Error('Readiness connection failed');
  }
  catch (error) { failed = true; throw error; }
  finally { client.removeListener('error', onError); client.release(failed); }
});
async function closeStorage(): Promise<void> {
  try {
    const results = await Promise.allSettled([callbackStore?.close(), sessionStore?.close()]);
    if (results.some((result) => result.status === 'rejected')) throw new Error('Storage shutdown failed');
  } finally { await pool?.end(); }
}

let example: ReturnType<typeof createExample>;
try {
  callbackStore = pool
    ? new PostgresCallbackStateStore({ pool, schema: process.env.RP_DATABASE_SCHEMA })
    : new SqliteCallbackStateStore(process.env.CALLBACK_DB_PATH ?? './rp-callbacks.sqlite');
  sessionStore = pool
    ? new PostgresSessionStore({ pool, sessionSecret, namespace: base, schema: process.env.APP_DATABASE_SCHEMA })
    : new MemorySessionStore();
  if (callbackStore instanceof PostgresCallbackStateStore) await callbackStore.verifySchema();
  if (sessionStore instanceof PostgresSessionStore) await sessionStore.verifySchema();
  example = createExample({
    base, issuer, stateSecret, callbackStore, sessionStore,
    handleDomains: (process.env.HANDLE_DOMAINS ?? (dev ? 'example.com' : '')).split(',').map((d) => d.trim()).filter(Boolean),
    ready: async () => !stopping && await ready() && !stopping,
  });
} catch (error) {
  await closeStorage();
  throw error;
}
const { app, sweep } = example;

// Bounded batches, without overlapping maintenance jobs. Multiple hosts can safely run these.
let cleanup: Promise<unknown> | undefined;
const cleanupTimer = setInterval(() => {
  if (cleanup) return;
  cleanup = Promise.allSettled([
    sweep(),
    callbackStore instanceof PostgresCallbackStateStore ? callbackStore.cleanup(1000) : Promise.resolve(),
  ]).then((results) => {
    if (results.some((result) => result.status === 'rejected')) console.error('Storage cleanup failed; expired credentials remain unusable');
  }).finally(() => { cleanup = undefined; });
}, 60_000);
cleanupTimer.unref();

let server: ReturnType<typeof serve>;
try {
  server = serve({
    fetch: app.fetch,
    port,
    hostname: dev ? (baseUrl.hostname === '[::1]' ? '::1' : '127.0.0.1') : '0.0.0.0',
  }, () => console.log(`Example application at ${base}, accepting agents from ${issuer}`));
} catch (error) {
  clearInterval(cleanupTimer);
  await cleanup;
  await closeStorage();
  throw error;
}

async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  clearInterval(cleanupTimer);
  // Give ordinary requests time to finish, then close held-open connections before the platform kills us.
  const deadline = setTimeout(() => { if ('closeAllConnections' in server) server.closeAllConnections(); }, 15_000);
  deadline.unref();
  try {
    try {
      if (server.listening) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    } finally {
      await cleanup;
      await closeStorage();
    }
  } catch {
    console.error('Example application shutdown failed');
    process.exitCode = 1;
  } finally { clearTimeout(deadline); }
}
server.once('error', () => {
  console.error('Example application listener failed');
  process.exitCode = 1;
  void shutdown();
});
process.once('SIGINT', () => { void shutdown(); });
process.once('SIGTERM', () => { void shutdown(); });
