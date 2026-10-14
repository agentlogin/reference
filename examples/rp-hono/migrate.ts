#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { PostgresSessionStore } from './postgres-session-store.js';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`Install the example application's PostgreSQL session schema

Usage: RP_DATABASE_URL=postgresql://... npm run example:migrate

Environment:
  RP_DATABASE_URL       Required connection string for a DDL-capable migration role
  APP_DATABASE_SCHEMA   Schema name (default: agentlogin_app)

BASE_URL and SESSION_SECRET are not required: migration does not encrypt, decrypt,
or read application sessions. Application servers must share their own configured
BASE_URL and SESSION_SECRET. This migration is separate from npm run rp:migrate.`);
} else if (!process.env.RP_DATABASE_URL) {
  console.error('RP_DATABASE_URL is required. APP_DATABASE_SCHEMA defaults to agentlogin_app.');
  process.exitCode = 1;
} else {
  let store: PostgresSessionStore | undefined;
  try {
    store = new PostgresSessionStore({
      connectionString: process.env.RP_DATABASE_URL,
      schema: process.env.APP_DATABASE_SCHEMA,
      maxConnections: 1,
      // Constructor-only placeholders: migrations never perform session lookup or encryption.
      sessionSecret: randomBytes(32).toString('base64url'),
      namespace: 'migration-only',
    });
    await store.migrate();
    await store.verifySchema();
    console.log(`Application session PostgreSQL schema ${store.schema} is ready.`);
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^[A-Z0-9_]+$/.test(error.code) ? error.code : undefined;
    console.error('Application session migration failed. Check connectivity, DDL privileges, and APP_DATABASE_SCHEMA configuration.', { code });
    process.exitCode = 1;
  } finally {
    try { await store?.close(); }
    catch { console.error('Unable to close the migration connection pool.'); process.exitCode = 1; }
  }
}
