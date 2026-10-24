import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { connectionString, skipPostgres } from './helpers.js';

const run = promisify(execFile);

for (const operation of ['read', 'mutate', 'migrate']) {
  test(`PostgreSQL backend termination during ${operation} rejects without crashing its process`, { skip: skipPostgres }, async () => {
    assert.ok(connectionString, 'REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
    const schema = `disconnect_${randomUUID().replaceAll('-', '')}`;
    // Use a child so an unhandled pg.Client error cannot be hidden by the test runner's exception handling.
    const script = `
      import assert from 'node:assert/strict';
      import { Pool } from 'pg';
      import { PgDatabase, UncertainCommitError } from ${JSON.stringify(new URL('../src/runtime.ts', import.meta.url).href)};
      const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
      const schema = ${JSON.stringify(schema)};
      const admin = new Pool({ connectionString, max: 1 });
      const pool = new Pool({ connectionString, max: 1 });
      let terminated = false;
      async function terminate(client) {
        const { rows } = await client.query('SELECT pg_backend_pid() AS pid');
        const ended = new Promise(resolve => client.once('end', resolve));
        await admin.query('SELECT pg_terminate_backend($1)', [rows[0].pid]);
        terminated = true;
        await ended;
      }
      const operation = ${JSON.stringify(operation)};
      if (operation === 'migrate') {
        pool.on('connect', client => {
          const query = client.query.bind(client);
          client.query = async (...args) => {
            if (typeof args[0] === 'string' && args[0].startsWith('CREATE SCHEMA')) {
              client.query = query;
              await terminate(client);
            }
            return query(...args);
          };
        });
      }
      const db = new PgDatabase({ pool, schema, onCheckpoint: async event => {
        if (operation === 'mutate' && event.phase === 'afterBegin') await terminate(event.client);
      } });
      try {
        const action = operation === 'read' ? db.read(async session => { await terminate(session.client); return true; })
          : operation === 'mutate' ? db.mutate('terminate', async () => { throw new Error('mutation ran after disconnect'); })
          : db.migrate();
        await assert.rejects(action, error => !(error instanceof UncertainCommitError) && /terminat|connection|queryable/i.test(error.message));
        assert.equal(terminated, true);
        assert.equal(await db.read(async session => (await session.query('SELECT 42 AS answer')).rows[0].answer), 42);
        console.log('terminated operation failed closed; replacement connection works');
      } finally {
        await db.close();
        await pool.end();
        await admin.query('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE');
        await admin.end();
      }
    `;
    const { stdout, stderr } = await run(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], {
      env: { ...process.env, AGENTLOGIN_TEST_POSTGRES_URL: connectionString }, timeout: 20_000,
    });
    assert.match(stdout, /failed closed; replacement connection works/);
    assert.doesNotMatch(stderr, /Unhandled 'error' event/);
  });
}
