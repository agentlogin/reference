import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { createIssuer, LEGACY_SIGNING_CACHE_SECONDS, LEGACY_SIGNING_OVERLAP_SECONDS, loadSigningKey } from '../../issuer/src/index.js';
import { schemaV1, schemaV2 } from '../src/schema.js';
import { fixture, quote, skipPostgres } from './helpers.js';

const privateJwk = async () => exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey);

for (const version of [1, 2]) test(`PostgreSQL version ${version} upgrade fixes legacy signing retention at migration time`, { skip: skipPostgres }, async (t) => {
  let rejectPublication = false;
  const f = await fixture(t, { onCheckpoint: ({ operation, phase }) => {
    if (rejectPublication && operation === 'publishSigningKeys' && phase === 'beforeCommit') throw new Error('test publication rollback');
  } });
  const { schema, store, peer } = f;
  await f.admin.query(`DROP SCHEMA ${quote(schema)} CASCADE`);
  await f.admin.query(`CREATE SCHEMA ${quote(schema)}`);
  await f.admin.query(schemaV1(schema));
  if (version === 2) await f.admin.query(schemaV2(schema));
  await f.admin.query(`CREATE TABLE ${quote(schema)}.schema_migrations(version integer PRIMARY KEY)`);
  await f.admin.query(`INSERT INTO ${quote(schema)}.schema_migrations(version) VALUES($1)`, [version]);
  await f.admin.query(`CREATE SEQUENCE ${quote(schema)}.test_clock START WITH ${f.now()}`);
  await f.admin.query(`CREATE OR REPLACE FUNCTION ${quote(schema)}.app_now() RETURNS double precision LANGUAGE sql VOLATILE AS 'SELECT last_value::double precision FROM ${quote(f.schema)}.test_clock'`);
  const oldJwk = await privateJwk(), nextJwk = await privateJwk(), emergencyJwk = await privateJwk();
  const oldKey = await loadSigningKey(oldJwk), nextKey = await loadSigningKey(nextJwk), emergencyKey = await loadSigningKey(emergencyJwk);
  const token = await new SignJWT({ sub: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: oldKey.kid })
    .setIssuer('https://issuer.example').setAudience('rp').setIssuedAt(f.now()).setExpirationTime(f.now() + 600).sign(oldKey.privateKey);
  await store.migrate();
  const deadline = f.now() + LEGACY_SIGNING_OVERLAP_SECONDS;
  await f.advance(20);
  await peer.migrate();
  await assert.rejects(async () => store.publishSigningKeys([
    { kid: oldKey.kid, publicJwk: oldKey.publicJwk }, { kid: 'invalid', publicJwk: { ...oldKey.publicJwk, d: 'private' } },
  ], oldKey.kid, 0, 0), /public key/);
  assert.deepEqual(await store.listSigningKeys(), []);
  const options = { issuer: 'https://issuer.example', handleDomains: ['example.com'], signingJwks: [oldJwk, nextJwk, emergencyJwk], jwksCacheSeconds: 0 };
  rejectPublication = true;
  await assert.rejects(createIssuer({ ...options, store }), /test publication rollback/);
  rejectPublication = false;
  assert.deepEqual(await peer.listSigningKeys(), [], 'a failed transfer publishes none of the ring');
  const issuer = await createIssuer({ ...options, store });
  assert.ok((await peer.listSigningKeys()).every((key) => key.retireNotBefore === deadline));
  await f.advance(1);
  assert.equal(await issuer.activateSigningKey(nextKey.kid), true);
  assert.equal(await issuer.removeSigningKey(oldKey.kid), false);
  assert.equal(await issuer.removeSigningKey(emergencyKey.kid, true), true);
  const jwks = await (await issuer.app.request('/.well-known/jwks.json')).json();
  await jwtVerify(token, createLocalJWKSet(jwks), { issuer: 'https://issuer.example', audience: 'rp', currentDate: new Date(f.now() * 1000) });
  await f.advance(20);
  await createIssuer({ ...options, signingJwks: [oldJwk, nextJwk], store: peer });
  assert.equal((await peer.listSigningKeys()).find((key) => key.kid === oldKey.kid)?.retireNotBefore, deadline);
  const reservation = await peer.reserveSigningKey(f.now() + 600, 0);
  const issuingDeadline = reservation!.lastIssuedExpiresAt! + LEGACY_SIGNING_CACHE_SECONDS;
  assert.equal(reservation?.retireNotBefore, issuingDeadline, 'new reservations preserve the legacy maximum including the PostgreSQL issuance lease');
  const [later] = await issuer.publishSigningKeys([await privateJwk()]);
  assert.equal((await peer.listSigningKeys()).find((key) => key.kid === later)?.retireNotBefore, undefined);
  assert.equal(await peer.removeSigningKey(later!, false, 0), true);
  await f.advance(deadline - f.now() - 1);
  assert.equal(await peer.removeSigningKey(oldKey.kid, false, 0), false);
  await f.advance(1);
  assert.equal(await peer.removeSigningKey(oldKey.kid, false, 0), true);
  const [replacement] = await issuer.publishSigningKeys([await privateJwk()]);
  await f.advance(1);
  assert.equal(await issuer.activateSigningKey(replacement!), true);
  assert.equal(await peer.removeSigningKey(nextKey.kid, false, 0), false);
  await f.advance(issuingDeadline - f.now() - 1);
  assert.equal(await peer.removeSigningKey(nextKey.kid, false, 0), false);
  await f.advance(1);
  assert.equal(await peer.removeSigningKey(nextKey.kid, false, 0), true);
});

test('PostgreSQL fresh installation does not inherit a legacy signing delay', { skip: skipPostgres }, async (t) => {
  const f = await fixture(t);
  const keys = await Promise.all([privateJwk(), privateJwk()]);
  const issuer = await createIssuer({ issuer: 'https://issuer.example', handleDomains: [], signingJwks: keys, store: f.store, jwksCacheSeconds: 0 });
  assert.ok((await f.store.listSigningKeys()).every((key) => key.retireNotBefore === undefined));
  assert.equal(await issuer.removeSigningKey((await loadSigningKey(keys[1])).kid), true);
});
