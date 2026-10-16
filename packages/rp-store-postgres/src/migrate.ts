#!/usr/bin/env node
import { PostgresCallbackStateStore } from './postgres-callback-store.js';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`agentlogin-rp-migrate - install the Agent Login RP callback schema

Usage: RP_DATABASE_URL=postgresql://... agentlogin-rp-migrate

Environment:
  RP_DATABASE_URL      Required connection string for a DDL-capable migration role
  RP_DATABASE_SCHEMA   Schema name (default: agentlogin_rp)

Applications verify the installed schema at startup; callback requests never migrate it.`);
} else if (!process.env.RP_DATABASE_URL) {
  console.error('RP_DATABASE_URL is required to migrate RP callback storage. RP_DATABASE_SCHEMA defaults to agentlogin_rp.');
  process.exitCode = 1;
} else {
  let store: PostgresCallbackStateStore | undefined;
  try {
    store = new PostgresCallbackStateStore({
      connectionString: process.env.RP_DATABASE_URL,
      schema: process.env.RP_DATABASE_SCHEMA,
      maxConnections: 1,
    });
    await store.migrate();
    await store.verifySchema();
    console.log(`RP callback PostgreSQL schema ${store.schema} is ready.`);
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^[A-Z0-9_]+$/.test(error.code) ? error.code : undefined;
    console.error('RP callback migration failed. Check connectivity, DDL privileges, and RP_DATABASE_SCHEMA configuration.', { code });
    process.exitCode = 1;
  } finally {
    try { await store?.close(); }
    catch { console.error('Unable to close the migration connection pool.'); process.exitCode = 1; }
  }
}
