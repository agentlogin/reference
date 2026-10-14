// Runs the example application.
//
//   ISSUER          Issuer to accept (default http://localhost:3000, the reference issuer in development mode)
//   BASE_URL        this application's public URL (default http://localhost:4000)
//   HANDLE_DOMAINS  for local development: handle domains served by ISSUER, mapped without WebFinger
//   STATE_SECRET    at least 32 characters; required outside development
//   RP_DATABASE_URL PostgreSQL callback storage, shared across hosts; run npm run rp:migrate first
//   RP_DATABASE_SCHEMA PostgreSQL schema (default agentlogin_rp)
//   CALLBACK_DB_PATH local SQLite fallback when RP_DATABASE_URL is absent (default ./rp-callbacks.sqlite)
import { serve } from '@hono/node-server';
import { SqliteCallbackStateStore } from '@agentlogin/rp';
import { PostgresCallbackStateStore } from '@agentlogin/rp-store-postgres';
import { createExample } from './app.js';

const base = process.env.BASE_URL ?? 'http://localhost:4000';
const issuer = process.env.ISSUER ?? 'http://localhost:3000'; // exactly as the Issuer publishes it
const baseUrl = new URL(base);
const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(baseUrl.hostname);
const dev = baseUrl.protocol === 'http:' && loopback;
if (baseUrl.protocol !== 'https:' && !dev) throw new Error('BASE_URL must use HTTPS outside loopback development');
if (!dev && !process.env.STATE_SECRET) throw new Error('STATE_SECRET is required outside development');

const callbackStore = process.env.RP_DATABASE_URL
  ? new PostgresCallbackStateStore({
      connectionString: process.env.RP_DATABASE_URL,
      schema: process.env.RP_DATABASE_SCHEMA,
    })
  : new SqliteCallbackStateStore(process.env.CALLBACK_DB_PATH ?? './rp-callbacks.sqlite');
if (callbackStore instanceof PostgresCallbackStateStore) {
  try { await callbackStore.verifySchema(); }
  catch (error) { await callbackStore.close(); throw error; }
}

let example: ReturnType<typeof createExample>;
try {
  example = createExample({
    base,
    issuer,
    stateSecret: process.env.STATE_SECRET ?? 'development-only-secret-development-only', // loopback listener only
    callbackStore,
    handleDomains: (process.env.HANDLE_DOMAINS ?? (dev ? 'example.com' : '')).split(',').map((d) => d.trim()).filter(Boolean),
  });
} catch (error) {
  await callbackStore.close();
  throw error;
}
const { app, sweep } = example;
const sessionTimer = setInterval(sweep, 60_000);
sessionTimer.unref(); // sessions and Access Tokens end on the server, not only in the cookie

// One bounded batch per minute, with no overlapping cleanup jobs. Multiple hosts can safely run this.
let cleanup: Promise<unknown> | undefined;
const cleanupTimer = callbackStore instanceof PostgresCallbackStateStore
  ? setInterval(() => {
      if (cleanup) return;
      cleanup = callbackStore.cleanup(1000)
        .catch(() => console.error('Callback cleanup failed; expired states remain unusable'))
        .finally(() => { cleanup = undefined; });
    }, 60_000)
  : undefined;
cleanupTimer?.unref();

const server = serve({
  fetch: app.fetch,
  port: Number(baseUrl.port || 4000),
  hostname: dev ? (baseUrl.hostname === '[::1]' ? '::1' : '127.0.0.1') : '0.0.0.0',
}, () => console.log(`Example application at ${base}, accepting agents from ${issuer}`));

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  clearInterval(sessionTimer);
  if (cleanupTimer) clearInterval(cleanupTimer);
  try {
    try {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    } finally {
      await cleanup;
      await callbackStore.close();
    }
  } catch {
    console.error('Example application shutdown failed');
    process.exitCode = 1;
  }
}
process.once('SIGINT', () => { void shutdown(); });
process.once('SIGTERM', () => { void shutdown(); });
