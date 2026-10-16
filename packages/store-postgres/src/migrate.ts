#!/usr/bin/env node
import { PgDatabase } from './runtime.js';
import { SCHEMA_VERSION } from './schema.js';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`agentlogin-migrate — install or update the Agent Login PostgreSQL schema

Usage: DATABASE_URL=postgresql://… agentlogin-migrate

Environment:
  DATABASE_URL        Required connection string for a DDL-capable migration role
  DATABASE_SCHEMA     Schema name (default: agentlogin)
  DATABASE_POOL_SIZE  Connection limit (default: 1)

The issuer verifies the installed schema at startup and does not migrate it.`);
} else if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required to migrate the issuer database. DATABASE_SCHEMA defaults to agentlogin.');
  process.exitCode = 1;
} else {
  let database: PgDatabase | undefined;
  try {
    database = new PgDatabase({
      connectionString: process.env.DATABASE_URL,
      schema: process.env.DATABASE_SCHEMA,
      maxConnections: process.env.DATABASE_POOL_SIZE === undefined ? 1 : Number(process.env.DATABASE_POOL_SIZE),
    });
    await database.migrate();
    await database.verifySchema();
    console.log(`Issuer PostgreSQL schema ${database.schema} is at version ${SCHEMA_VERSION}.`);
  } catch (error) {
    // Driver messages/details can contain URLs, complete row payloads, credentials, or personal information.
    const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^[A-Z0-9_]+$/.test(error.code) ? error.code : undefined;
    console.error('Issuer PostgreSQL migration failed. Check database connectivity, DDL privileges, and DATABASE_SCHEMA configuration.', { code });
    process.exitCode = 1;
  } finally {
    try { await database?.close(); }
    catch { console.error('Unable to close the migration connection pool.'); process.exitCode = 1; }
  }
}
