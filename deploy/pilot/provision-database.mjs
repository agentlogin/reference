#!/usr/bin/env node
// Operator-only provisioning. No passwords, customer-data reads, or cloud API calls.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { Client, Pool } from 'pg';

const identifier = value => {
  assert.ok(typeof value === 'string' && /^[a-z_][a-z0-9_]{0,62}$/.test(value) && !value.startsWith('pg_'), 'Invalid identifier');
  return value;
};
const q = value => `"${identifier(value)}"`;
export function settings(input = {}) {
  const out = { database: 'agent_workspace', runtime: 'agent_workspace_runtime', migrator: 'agent_workspace_migrator', callbackSchema: 'agentlogin_rp', appSchema: 'agentlogin_app', ...input };
  for (const value of Object.values(out)) identifier(value);
  assert.notEqual(out.runtime, out.migrator);
  assert.notEqual(out.callbackSchema, out.appSchema);
  assert.ok(!['postgres', 'template0', 'template1'].includes(out.database), 'Use a new dedicated database');
  return out;
}
const marker = o => `agentlogin-workspace-v1:${o.database}`;

export function connectionOptions(env = process.env, database) {
  const url = new URL(env.DATABASE_URL);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol) && url.hostname && !url.search && !url.hash, 'Invalid database URL or query overrides');
  assert.notEqual(env.NODE_TLS_REJECT_UNAUTHORIZED, '0', 'TLS verification must remain enabled');
  if (database) url.pathname = '/' + identifier(database);
  const transport = env.PILOT_DATABASE_TRANSPORT ?? 'tls';
  let ssl;
  if (transport === 'tls') ssl = { rejectUnauthorized: true, ...(env.PILOT_DATABASE_CA_FILE ? { ca: readFileSync(env.PILOT_DATABASE_CA_FILE, 'utf8') } : {}) };
  else if (transport === 'railway-private') {
    assert.match(url.hostname, /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.railway\.internal$/);
    for (const name of ['RAILWAY_PROJECT_ID', 'RAILWAY_ENVIRONMENT_ID']) assert.match(env[name] ?? '', /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
    ssl = false;
  } else {
    assert.equal(transport, 'loopback-test');
    assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Test transport is loopback only');
    ssl = false;
  }
  return { connectionString: url.href, ssl, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 5_000,
    query_timeout: 15_000, options: '-c synchronous_commit=on -c statement_timeout=10000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000 -c search_path=pg_catalog' };
}
export async function withClient(config, operation) {
  const client = new Client(config);
  client.on('error', () => {}); // Never log raw driver errors: they can contain credentials.
  try { await client.connect(); return await operation(client); }
  finally { await client.end(); }
}
async function primary(client, expectedDatabase) {
  const row = (await client.query(`SELECT current_database() AS database, pg_is_in_recovery() AS recovery,
    current_setting('transaction_read_only') AS read_only, current_setting('synchronous_commit') AS synchronous_commit,
    current_setting('server_version_num')::integer AS version`)).rows[0];
  assert.ok(!row.recovery && row.read_only === 'off' && row.synchronous_commit === 'on', 'Writable durable primary required');
  assert.ok(row.version >= 170000, 'PostgreSQL 17 or newer is required');
  if (expectedDatabase) assert.equal(row.database, expectedDatabase, 'Wrong database');
  return row;
}
export function plan(phase, input = {}) {
  const o = settings(input), db = q(o.database), runtime = q(o.runtime), migrator = q(o.migrator);
  const cb = q(o.callbackSchema), app = q(o.appSchema);
  if (phase === 'bootstrap') return [
    'BEGIN',
    `CREATE ROLE ${runtime} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 24`,
    `CREATE ROLE ${migrator} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2`,
    `COMMENT ON ROLE ${runtime} IS '${marker(o)}'`, `COMMENT ON ROLE ${migrator} IS '${marker(o)}'`, 'COMMIT',
    `CREATE DATABASE ${db} OWNER ${migrator} TEMPLATE template0 ALLOW_CONNECTIONS false CONNECTION LIMIT 32`,
    `COMMENT ON DATABASE ${db} IS '${marker(o)}'`,
    `REVOKE ALL PRIVILEGES ON DATABASE ${db} FROM PUBLIC`,
    `GRANT CONNECT ON DATABASE ${db} TO ${runtime}, ${migrator}`,
    `ALTER DATABASE ${db} SET synchronous_commit = 'on'`,
    `ALTER DATABASE ${db} ALLOW_CONNECTIONS true`,
  ];
  if (phase === 'grants') return [
    'BEGIN',
    `REVOKE ALL PRIVILEGES ON DATABASE ${db} FROM PUBLIC, ${runtime}`,
    `GRANT CONNECT ON DATABASE ${db} TO ${runtime}`,
    'REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC',
    `REVOKE ALL PRIVILEGES ON SCHEMA ${cb}, ${app} FROM PUBLIC, ${runtime}`,
    `GRANT USAGE ON SCHEMA ${cb}, ${app} TO ${runtime}`,
    `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${cb}, ${app} FROM PUBLIC, ${runtime}`,
    `REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ${cb}, ${app} FROM PUBLIC, ${runtime}`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${cb}.callback_states, ${app}.app_accounts, ${app}.app_sessions, ${app}.app_notes TO ${runtime}`,
    `GRANT SELECT ON ${cb}.schema_migrations, ${app}.app_schema_migrations TO ${runtime}`,
    `GRANT EXECUTE ON FUNCTION ${cb}.app_now_ms(), ${app}.app_now() TO ${runtime}`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migrator} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`,
    ...Object.entries({ synchronous_commit: 'on', statement_timeout: '10s', lock_timeout: '5s', idle_in_transaction_session_timeout: '30s', search_path: 'pg_catalog' })
      .map(([name, value]) => `ALTER ROLE ${runtime} IN DATABASE ${db} SET ${name} = '${value}'`),
    'COMMIT',
  ];
  assert.ok(['migrate', 'verify'].includes(phase), 'Unknown phase');
  return phase === 'migrate' ? [
    `Connect to ${o.database}; verify ownership and operator markers`,
    `SET ROLE ${migrator} on every connection before migration SQL`,
    'Run compiled PostgresCallbackStateStore.migrate()/verifySchema()',
    'Run compiled PostgresSessionStore.migrate()/verifySchema()',
  ] : ['Verify database/role/schema/table/function ownership and exact runtime rights',
    `SET ROLE ${runtime}; run rollback-only negative DDL probes and compiled schema checks`,
    'No login/password setup or application-data reads'];
}
async function runStatements(client, statements) {
  try { for (const sql of statements) await client.query(sql); }
  catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
}
export async function bootstrap(client, input = {}) {
  const o = settings(input);
  await primary(client);
  assert.equal((await client.query('SELECT 1 FROM pg_database WHERE datname=$1', [o.database])).rowCount, 0, 'Database already exists; inspect before continuing');
  assert.equal((await client.query('SELECT 1 FROM pg_roles WHERE rolname=ANY($1)', [[o.runtime, o.migrator]])).rowCount, 0, 'Roles already exist; never repurpose them');
  await runStatements(client, plan('bootstrap', o));
}
async function provenance(client, o) {
  await primary(client, o.database);
  const db = (await client.query(`SELECT pg_get_userbyid(datdba) AS owner, shobj_description(oid,'pg_database') AS marker
    FROM pg_database WHERE datname=$1`, [o.database])).rows[0];
  assert.equal(db?.owner, o.migrator, 'Unexpected database owner');
  assert.equal(db?.marker, marker(o), 'Unrecognized database');
  const roles = (await client.query(`SELECT oid,rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit,rolconnlimit,rolcanlogin,
    shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=ANY($1)`, [[o.runtime, o.migrator]])).rows;
  assert.equal(roles.length, 2);
  for (const r of roles) {
    assert.equal(r.marker, marker(o), 'Unrecognized role');
    assert.ok(!r.rolsuper && !r.rolcreatedb && !r.rolcreaterole && !r.rolreplication && !r.rolbypassrls && !r.rolinherit, 'Privileged role');
    assert.ok(r.rolconnlimit > 0 && r.rolconnlimit <= (r.rolname === o.runtime ? 24 : 2), 'Unbounded role connections');
    assert.equal((await client.query('SELECT 1 FROM pg_auth_members WHERE member=$1', [r.oid])).rowCount, 0, 'Role membership permits escalation');
  }
  return roles;
}
async function stores(pool, o) {
  const [{ PostgresCallbackStateStore }, { PostgresSessionStore }] = await Promise.all([
    import('@agentlogin/rp-store-postgres'), import('agentlogin-example-rp-hono/postgres-session-store'),
  ]);
  return [new PostgresCallbackStateStore({ pool, schema: o.callbackSchema }),
    new PostgresSessionStore({ pool, schema: o.appSchema, namespace: 'operator-schema-check-only', sessionSecret: randomBytes(32).toString('hex') })];
}
async function scopedPool(config, role, operation) {
  const pool = new Pool(config);
  const ended = [];
  pool.on('connect', client => {
    client.on('error', () => {}); // Covers SET ROLE before an adapter installs its checked-out-client handler.
    ended.push(new Promise(resolve => client.once('end', resolve)));
  });
  pool.on('error', () => {});
  const scoped = {
    on: pool.on.bind(pool), removeListener: pool.removeListener.bind(pool),
    async connect() {
      const client = await pool.connect();
      try { await client.query(`SET ROLE ${q(role)}`); return client; }
      catch (error) { client.release(true); throw error; }
    },
  };
  try { return await operation(scoped); }
  finally { await pool.end(); await Promise.all(ended); }
}
export async function migrate(config, input = {}) {
  const o = settings(input);
  await withClient(config, async client => {
    await provenance(client, o);
    await client.query('REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC');
    await client.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${q(o.migrator)} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`);
  });
  await scopedPool(config, o.migrator, async pool => {
    const adapters = await stores(pool, o);
    try { for (const store of adapters) { await store.migrate(); await store.verifySchema(); } }
    finally { for (const store of adapters) await store.close(); }
  });
}
export async function grants(client, input = {}) {
  const o = settings(input);
  await provenance(client, o);
  for (const schema of [o.callbackSchema, o.appSchema]) {
    const found = (await client.query('SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname=$1', [schema])).rows[0];
    assert.equal(found?.owner, o.migrator, 'Unexpected schema owner');
  }
  await runStatements(client, plan('grants', o));
}
export async function verify(client, input = {}) {
  const o = settings(input), roles = await provenance(client, o);
  assert.equal((await client.query("SELECT has_parameter_privilege($1,'session_replication_role','SET') AS allowed", [o.runtime])).rows[0].allowed, false, 'Runtime can disable triggers');
  for (const right of ['CREATE', 'TEMP']) assert.equal((await client.query('SELECT has_database_privilege($1,$2,$3) AS allowed', [o.runtime, o.database, right])).rows[0].allowed, false, 'Runtime can create database objects');
  const schemas = (await client.query(`SELECT nspname,pg_get_userbyid(nspowner) AS owner,has_schema_privilege($1,oid,'CREATE') AS create
    FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'`, [o.runtime])).rows;
  assert.ok(schemas.every(s => !s.create && s.owner !== o.runtime), 'Runtime owns or can alter a schema');
  for (const schema of [o.callbackSchema, o.appSchema]) assert.equal(schemas.find(s => s.nspname === schema)?.owner, o.migrator);
  const tables = (await client.query(`SELECT n.nspname AS schema,c.relname AS name,pg_get_userbyid(c.relowner) AS owner,
    has_table_privilege($1,c.oid,'SELECT') AS select,has_table_privilege($1,c.oid,'INSERT') AS insert,
    has_table_privilege($1,c.oid,'UPDATE') AS update,has_table_privilege($1,c.oid,'DELETE') AS delete,
    has_any_column_privilege($1,c.oid,'INSERT') AS column_insert,has_any_column_privilege($1,c.oid,'UPDATE') AS column_update,
    has_table_privilege($1,c.oid,'TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS administrative
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname=ANY($2)`, [o.runtime, [o.callbackSchema, o.appSchema]])).rows;
  const required = new Set([`${o.callbackSchema}.callback_states`, `${o.callbackSchema}.schema_migrations`, ...['app_accounts','app_sessions','app_notes','app_schema_migrations'].map(t => `${o.appSchema}.${t}`)]);
  assert.equal(tables.length, required.size);
  for (const t of tables) {
    assert.ok(required.delete(`${t.schema}.${t.name}`) && t.owner === o.migrator && t.select && !t.administrative, 'Unexpected table ownership/rights');
    const writes = !['schema_migrations','app_schema_migrations'].includes(t.name);
    assert.equal(t.insert, writes); assert.equal(t.update, writes); assert.equal(t.delete, writes);
    assert.equal(t.column_insert, writes); assert.equal(t.column_update, writes);
  }
  const functions = (await client.query(`SELECT n.nspname AS schema,p.proname AS name,p.pronargs,p.prosecdef,p.proconfig,
    pg_get_userbyid(p.proowner) AS owner,has_function_privilege($1,p.oid,'EXECUTE') AS execute
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY($2)`, [o.runtime,[o.callbackSchema,o.appSchema]])).rows;
  assert.equal(functions.length, 2);
  for (const [schema,name] of [[o.callbackSchema,'app_now_ms'],[o.appSchema,'app_now']]) {
    const f = functions.find(f => f.schema === schema && f.name === name);
    assert.ok(f && f.pronargs === 0 && !f.prosecdef && f.owner === o.migrator && f.execute && f.proconfig?.includes('search_path=pg_catalog'), 'Unsafe clock function');
  }
  await client.query('BEGIN');
  try {
    await client.query(`SET LOCAL ROLE ${q(o.runtime)}`);
    for (const sql of [`CREATE SCHEMA workspace_forbidden_probe`, `CREATE TEMP TABLE workspace_forbidden_probe(id int)`,
      `CREATE TABLE ${q(o.appSchema)}.workspace_forbidden_probe(id int)`,
      `ALTER TABLE ${q(o.appSchema)}.app_sessions ADD COLUMN workspace_forbidden_probe int`,
      `UPDATE ${q(o.appSchema)}.app_schema_migrations SET version=version`]) {
      await client.query('SAVEPOINT privilege_probe');
      let denied = false;
      try { await client.query(sql); } catch (error) { if (error.code !== '42501') throw error; denied = true; }
      finally { await client.query('ROLLBACK TO SAVEPOINT privilege_probe'); }
      assert.ok(denied, 'Runtime unexpectedly allowed a DDL or migration-table write');
    }
  } finally { await client.query('ROLLBACK'); }
  // LIMIT 0/schema-version queries and clock reads only; never application session/note rows.
  await client.query(`SET ROLE ${q(o.runtime)}`);
  const facade = { on: client.on.bind(client), removeListener: client.removeListener.bind(client), connect: async () => ({ query: client.query.bind(client), on: client.on.bind(client), removeListener: client.removeListener.bind(client), release() {} }) };
  const adapters = await stores(facade, o);
  try { for (const store of adapters) await store.verifySchema(); }
  finally { for (const store of adapters) await store.close(); await client.query('RESET ROLE'); }
  return { verified: true, database: o.database, runtimeRole: o.runtime, runtimeLoginEnabled: roles.find(r => r.rolname === o.runtime).rolcanlogin, ddlDenied: true, credentialsTested: false };
}

async function main() {
  const { values } = parseArgs({ options: { phase: { type: 'string' }, apply: { type: 'boolean' }, help: { type: 'boolean' } }, strict: true });
  if (values.help) { console.log('Usage: node deploy/pilot/provision-database.mjs --phase bootstrap|migrate|grants|verify [--apply]\nWithout --apply: print a secret-free plan. DATABASE_URL supplies operator access only during apply. Roles start NOLOGIN; passwords and LOGIN are managed separately.'); return; }
  const o = settings({ database: process.env.PILOT_DATABASE_NAME ?? 'agent_workspace', runtime: process.env.PILOT_RUNTIME_ROLE ?? 'agent_workspace_runtime', migrator: process.env.PILOT_MIGRATOR_ROLE ?? 'agent_workspace_migrator' });
  const steps = plan(values.phase, o);
  if (!values.apply) { console.log(JSON.stringify({ phase: values.phase, settings: o, statements: steps }, null, 2)); return; }
  const config = connectionOptions(process.env, values.phase === 'bootstrap' ? undefined : o.database);
  let result;
  if (values.phase === 'migrate') await migrate(config, o);
  else result = await withClient(config, client => ({ bootstrap, grants, verify })[values.phase](client, o));
  console.log(JSON.stringify(result ?? { completed: true, phase: values.phase, database: o.database }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error('Workspace provisioning failed. The outcome may be partial or uncertain; inspect the named database and roles before retrying. No automatic cleanup or password changes were attempted.');
    process.exitCode = 1;
  });
}
