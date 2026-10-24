// Standalone server. Configuration by environment:
//   ISSUER           Issuer Identifier (default http://localhost:3000 in development)
//   HANDLE_DOMAINS   comma-separated handle domains (default: host of ISSUER)
//   PORT             listen port (default 3000)
//   ADMIN_TOKEN      bootstrap/registration token (generated and printed when absent)
//   SIGNING_JWK      private ES256 JWK as JSON (ephemeral when absent)
//   DATABASE_URL    PostgreSQL connection URL (requires @agentlogin/store-postgres and prior migration)
//   DATABASE_SCHEMA PostgreSQL schema (default agentlogin)
//   DATABASE_PATH   SQLite database path; mutually exclusive with DATABASE_URL
//   INSECURE_DEV=1   permit http issuer and loopback clients; print Owner sign-in codes instead of mailing them
import { readFile } from 'node:fs/promises';
import { serve } from '@hono/node-server';
import { createIssuer, SQLiteStore, validateSigningConfiguration, reloadSigningConfiguration, type Store } from './index.js';

const insecure = process.env.INSECURE_DEV === '1' || !process.env.ISSUER;
const issuer = process.env.ISSUER ?? 'http://localhost:3000';
const port = Number(process.env.PORT ?? new URL(issuer).port ?? 3000) || 3000;
const handleDomains = (process.env.HANDLE_DOMAINS ?? new URL(issuer).hostname).split(',').map((s) => s.trim()).filter(Boolean);
const adminToken = process.env.ADMIN_TOKEN;

// Persistent instances must share the same configured signing key as well as the database.
if (process.env.DATABASE_PATH && process.env.DATABASE_URL) throw new Error('Choose DATABASE_PATH or DATABASE_URL');
if (process.env.SIGNING_JWK && process.env.SIGNING_KEYS_FILE) throw new Error('Choose SIGNING_JWK or SIGNING_KEYS_FILE');
if ((process.env.DATABASE_PATH || process.env.DATABASE_URL) && !process.env.SIGNING_JWK && !process.env.SIGNING_KEYS_FILE) throw new Error('Persistent storage requires SIGNING_JWK');
const signingConfiguration=process.env.SIGNING_KEYS_FILE ? await validateSigningConfiguration(JSON.parse(await readFile(process.env.SIGNING_KEYS_FILE,'utf8'))) : undefined;
let store: Store | undefined;
let closeStore: (() => void | Promise<void>) | undefined;
if (process.env.DATABASE_URL) {
  // Optional adapter dependency: the issuer package remains usable without PostgreSQL installed.
  const adapterPackage = '@agentlogin/store-postgres';
  const { PostgresStore } = await import(adapterPackage);
  const postgres = new PostgresStore({ connectionString: process.env.DATABASE_URL,
    schema: process.env.DATABASE_SCHEMA ?? 'agentlogin', maxConnections: Number(process.env.DATABASE_POOL_SIZE ?? 10) });
  try { await postgres.db.verifySchema(); } catch (error) { await postgres.close(); throw error; }
  store = postgres;
  closeStore = () => postgres.close();
} else if (process.env.DATABASE_PATH) {
  const sqlite = new SQLiteStore(process.env.DATABASE_PATH);
  store = sqlite;
  closeStore = () => sqlite.close();
}
const instance = await createIssuer({
  issuer,
  handleDomains,
  store,
  allowInsecureClients: insecure,
  adminToken,
  signingJwks: signingConfiguration?.keys,
  ownerDeletionRetentionSeconds: Number(process.env.OWNER_DELETION_RETENTION_SECONDS ?? 0),
  policyUri: process.env.OP_POLICY_URI,
  signingJwk: process.env.SIGNING_JWK ? JSON.parse(process.env.SIGNING_JWK) : undefined,
  // Development only: the one-time code of the Owner email sign-in is printed instead of mailed. A deployment passes a mailer.
  sendOwnerCode: insecure ? ({ email, code }) => console.log(`INSECURE_DEV: one-time code for ${email}: ${code}`) : undefined,
});
const {app,ctx}=instance;
if (signingConfiguration) await reloadSigningConfiguration(instance,signingConfiguration);
let reloading=false;
if (process.env.SIGNING_KEYS_FILE) process.on('SIGHUP',()=>{
  if (reloading) return;
  reloading=true;
  void readFile(process.env.SIGNING_KEYS_FILE!,'utf8').then(JSON.parse).then((value)=>reloadSigningConfiguration(instance,value))
    .then(()=>console.log('Signing configuration reloaded'))
    .catch(()=>console.error('Signing configuration reload failed; inspect configuration and lifecycle state'))
    .finally(()=>{reloading=false;});
});
const server = serve({ fetch: app.fetch, port }, () => {
  console.log(`Agent Login issuer ${issuer} listening on :${port}; handle domains ${handleDomains.join(', ')}`);
  if (!adminToken) console.log(`ADMIN_TOKEN (generated): ${ctx.adminToken}`);
  if (insecure) console.log('INSECURE_DEV: http and loopback clients are permitted');
});

// Stop accepting requests, drain active handlers, then release pooled database connections.
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => {
  server.close(() => { void Promise.resolve(closeStore?.()).catch(() => { process.exitCode = 1; }); });
});
