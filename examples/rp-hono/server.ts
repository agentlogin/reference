// Runs the example application.
//
//   ISSUER          Issuer to accept (default http://localhost:3000, the reference issuer in development mode)
//   BASE_URL        this application's public URL (default http://localhost:4000)
//   HANDLE_DOMAINS  for local development: handle domains served by ISSUER, mapped without WebFinger
//   STATE_SECRET    at least 32 characters; required outside development
//   CALLBACK_DB_PATH SQLite file shared by every instance on this host (default ./rp-callbacks.sqlite)
import { serve } from '@hono/node-server';
import { SqliteCallbackStateStore } from '@agentlogin/rp';
import { createExample } from './app.js';

const base = process.env.BASE_URL ?? 'http://localhost:4000';
const issuer = process.env.ISSUER ?? 'http://localhost:3000'; // exactly as the Issuer publishes it
const dev = base.startsWith('http://');
if (!dev && !process.env.STATE_SECRET) throw new Error('STATE_SECRET is required outside development');

const { app, sweep } = createExample({
  base,
  issuer,
  stateSecret: process.env.STATE_SECRET ?? 'development-only-secret-development-only', // the fallback is reachable only over http on localhost
  callbackStore: new SqliteCallbackStateStore(process.env.CALLBACK_DB_PATH ?? './rp-callbacks.sqlite'),
  handleDomains: (process.env.HANDLE_DOMAINS ?? (dev ? 'example.com' : '')).split(',').map((d) => d.trim()).filter(Boolean),
});
setInterval(sweep, 60_000).unref(); // sessions and Access Tokens end on the server, not only in the cookie

serve({ fetch: app.fetch, port: Number(new URL(base).port || 4000) }, () => console.log(`Example application at ${base}, accepting agents from ${issuer}`));
