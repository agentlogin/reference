import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { Client } from 'pg';
import { settings, connectionOptions, plan, bootstrap, migrate, grants, verify, withClient } from '../../../deploy/pilot/provision-database.mjs';

const connectionString = process.env.AGENTLOGIN_TEST_POSTGRES_URL;
const skip = !connectionString && process.env.REQUIRE_POSTGRES_TESTS !== '1' ? 'AGENTLOGIN_TEST_POSTGRES_URL is not configured' : false;

test('operator plans contain no passwords or destructive cleanup and reject ambiguous identifiers/transports', () => {
  const o = settings();
  assert.equal(o.database, 'agent_workspace');
  for (const phase of ['bootstrap', 'migrate', 'grants', 'verify']) {
    const text = plan(phase, o).join('\n');
    assert.doesNotMatch(text, /DROP |PASSWORD|CREATEDB\s*[;,]/);
  }
  for (const database of ['postgres', 'template0', 'x;DROP ROLE x', 'x y', 'x'.repeat(64)]) assert.throws(() => settings({ database }));
  assert.throws(() => settings({ runtime: 'same', migrator: 'same' }));
  assert.throws(() => connectionOptions({ DATABASE_URL: 'postgresql://localhost/postgres?sslmode=disable' }));
  assert.throws(() => connectionOptions({ DATABASE_URL: 'postgresql://public.example/db', PILOT_DATABASE_TRANSPORT: 'loopback-test' }));
  assert.throws(() => connectionOptions({ DATABASE_URL: 'postgresql://private.railway.internal/db', PILOT_DATABASE_TRANSPORT: 'railway-private' }));
  assert.equal(connectionOptions({ DATABASE_URL: 'postgresql://localhost/postgres', PILOT_DATABASE_TRANSPORT: 'loopback-test' }).max, 1);
});

test('operator phases create only a dedicated database and restricted roles, migrate compiled schemas, and detect privilege drift', { skip, timeout: 30_000 }, async () => {
  assert.ok(connectionString, 'REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
  const suffix = randomBytes(8).toString('hex');
  const o = settings({ database: `workspace_test_${suffix}`, runtime: `workspace_runtime_${suffix}`, migrator: `workspace_migrate_${suffix}` });
  const config = { connectionString, max: 1, connectionTimeoutMillis: 5_000, query_timeout: 15_000,
    options: '-c synchronous_commit=on -c statement_timeout=10000 -c lock_timeout=5000' };
  const admin = new Client(config); admin.on('error', () => {});
  await admin.connect();
  const target = new URL(connectionString); target.pathname = '/' + o.database;
  const targetConfig = { ...config, connectionString: target.href };
  let created = false;
  try {
    await admin.query(`CREATE ROLE "${o.runtime}" NOLOGIN CREATEDB`);
    await assert.rejects(bootstrap(admin, o), /Roles already exist/);
    assert.equal((await admin.query('SELECT rolcreatedb FROM pg_roles WHERE rolname=$1', [o.runtime])).rows[0].rolcreatedb, true, 'an existing role is not repurposed');
    assert.equal((await admin.query('SELECT 1 FROM pg_database WHERE datname=$1', [o.database])).rowCount, 0);
    await admin.query(`DROP ROLE "${o.runtime}"`);
    await bootstrap(admin, o); created = true;
    await assert.rejects(bootstrap(admin, o), /already exists/);
    await withClient(targetConfig, async client => {
      assert.equal((await client.query("SELECT count(*)::integer AS n FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')")).rows[0].n, 0, 'template0 copied no application tables');
    });
    await migrate(targetConfig, o);
    await migrate(targetConfig, o);
    await withClient(targetConfig, async client => {
      await grants(client, o);
      await grants(client, o);
      const result = await verify(client, o);
      assert.equal(result.verified, true);
      assert.equal(result.runtimeLoginEnabled, false, 'bootstrap cannot open credential access');
      await client.query(`GRANT "${o.migrator}" TO "${o.runtime}"`);
      await assert.rejects(verify(client, o), /Role membership/);
      await client.query(`REVOKE "${o.migrator}" FROM "${o.runtime}"`);
      await client.query(`GRANT CREATE ON SCHEMA public TO "${o.runtime}"`);
      await assert.rejects(verify(client, o), /Runtime owns or can alter/);
      await client.query(`REVOKE CREATE ON SCHEMA public FROM "${o.runtime}"`);
      await client.query(`GRANT UPDATE(applied_at) ON agentlogin_app.app_schema_migrations TO "${o.runtime}"`);
      await assert.rejects(verify(client, o));
      await client.query(`REVOKE UPDATE(applied_at) ON agentlogin_app.app_schema_migrations FROM "${o.runtime}"`);
      await client.query(`GRANT SET ON PARAMETER session_replication_role TO "${o.runtime}"`);
      try { await assert.rejects(verify(client, o), /Runtime can disable triggers/); }
      finally { await client.query(`REVOKE SET ON PARAMETER session_replication_role FROM "${o.runtime}"`); }
      assert.equal((await verify(client, o)).verified, true);
    });
    // Synthetic test-only password; production password setup deliberately belongs to the operator.
    const password = randomBytes(32).toString('hex');
    await admin.query(`ALTER ROLE "${o.runtime}" LOGIN PASSWORD '${password}'`);
    target.username = o.runtime; target.password = password;
    await withClient({ ...config, connectionString: target.href }, async client => {
      assert.equal((await client.query('SELECT current_user')).rows[0].current_user, o.runtime);
      assert.equal((await verify(client, o)).verified, true);
      for (const table of ['app_accounts','app_sessions','app_notes']) assert.equal((await client.query(`SELECT count(*)::integer AS n FROM agentlogin_app.${table}`)).rows[0].n, 0);
      await assert.rejects(client.query('CREATE SCHEMA forbidden_runtime_schema'), { code: '42501' });
      await assert.rejects(client.query('CREATE TEMP TABLE forbidden_runtime_temp(id int)'), { code: '42501' });
    });
  } finally {
    // Remove only this test's random names. Never DROP OWNED in the operator's/customer database.
    if (created) await admin.query(`DROP DATABASE "${o.database}"`);
    await admin.query(`DROP ROLE IF EXISTS "${o.runtime}", "${o.migrator}"`);
    await admin.end();
  }
});
