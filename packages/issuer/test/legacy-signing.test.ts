import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { createIssuer, LEGACY_SIGNING_CACHE_SECONDS, LEGACY_SIGNING_OVERLAP_SECONDS, loadSigningKey, SQLiteStore, StoreState, type Store } from '../src/index.js';

const privateJwk = async () => exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey);

for (const adapter of ['memory', 'sqlite'] as const) for (const version of [1, 2]) {
  test(`${adapter}: version ${version} signing-history upgrade retains live tokens through the fixed conservative overlap`, async (t) => {
    let now = 1_700_000_000;
    const oldJwk = await privateJwk(), nextJwk = await privateJwk(), emergencyJwk = await privateJwk();
    const oldKey = await loadSigningKey(oldJwk), nextKey = await loadSigningKey(nextJwk), emergencyKey = await loadSigningKey(emergencyJwk);
    const token = await new SignJWT({ sub: 'agent' }).setProtectedHeader({ alg: 'ES256', kid: oldKey.kid })
      .setIssuer('https://issuer.example').setAudience('rp').setIssuedAt(now).setExpirationTime(now + 600).sign(oldKey.privateKey);
    const legacy = JSON.parse(new StoreState().exportSnapshot());
    legacy.version = version;
    delete legacy.maps.signingKeys;
    delete legacy.activeSigningKid;
    delete legacy.legacySigningHistory;
    let state = new StoreState(JSON.stringify(legacy));
    let sqlite: SQLiteStore | undefined;
    let path: string | undefined;
    if (adapter === 'sqlite') {
      const directory = mkdtempSync(join(tmpdir(), 'agentlogin-legacy-signing-'));
      path = join(directory, 'issuer.sqlite');
      sqlite = new SQLiteStore(path);
      sqlite.close();
      const database = new DatabaseSync(path);
      database.prepare('UPDATE agentlogin_state SET snapshot=? WHERE id=1').run(JSON.stringify(legacy));
      database.close();
      sqlite = new SQLiteStore(path);
      t.after(() => { sqlite?.close(); rmSync(directory, { recursive: true, force: true }); });
    }
    const store = () => (sqlite ?? state) as Store;
    const reopen = () => {
      if (sqlite) { sqlite.close(); sqlite = new SQLiteStore(path!); }
      else state = new StoreState(state.exportSnapshot());
    };
    // An unrelated mutation/restart cannot discard the still-pending migration guard.
    await store().putOwner({ id: 'owner', ownerSub: 'owner', email: 'owner@example.com', emailVerified: true, verifiedVia: 'oidc', createdAt: now });
    reopen();
    await assert.rejects(async () => store().publishSigningKeys([
      { kid: oldKey.kid, publicJwk: oldKey.publicJwk }, { kid: 'invalid', publicJwk: { ...oldKey.publicJwk, d: 'private' } },
    ], oldKey.kid, now, 0), /public key/);
    assert.deepEqual(await store().listSigningKeys(), []);
    reopen();
    const options = () => ({ issuer: 'https://issuer.example', handleDomains: ['example.com'], store: store(),
      signingJwks: [oldJwk, nextJwk, emergencyJwk], now: () => now, jwksCacheSeconds: 0 });
    let issuer = await createIssuer(options());
    const deadline = now + LEGACY_SIGNING_OVERLAP_SECONDS;
    assert.ok((await store().listSigningKeys()).every((key) => key.retireNotBefore === deadline));
    now++;
    assert.equal(await issuer.activateSigningKey(nextKey.kid), true);
    assert.equal(await issuer.removeSigningKey(oldKey.kid), false);
    assert.equal(await issuer.removeSigningKey(emergencyKey.kid, true), true, 'compromise overrides the upgrade floor immediately');
    const jwks = await (await issuer.app.request('/.well-known/jwks.json')).json();
    await jwtVerify(token, createLocalJWKSet(jwks), { issuer: 'https://issuer.example', audience: 'rp', currentDate: new Date(now * 1000) });
    // Restart with the surviving ring; neither restart nor publication extends the old deadline.
    now += 20;
    reopen();
    issuer = await createIssuer({ ...options(), signingJwks: [oldJwk, nextJwk] });
    assert.equal((await store().listSigningKeys()).find((key) => key.kid === oldKey.kid)?.retireNotBefore, deadline);
    const reservation = await store().reserveSigningKey(now + 600, now);
    const issuingDeadline = now + 600 + LEGACY_SIGNING_CACHE_SECONDS;
    assert.equal(reservation?.retireNotBefore, issuingDeadline, 'continued issuance preserves this legacy key\'s unknown historical cache bound');
    const [later] = await issuer.publishSigningKeys([await privateJwk()]);
    assert.equal((await store().listSigningKeys()).find((key) => key.kid === later)?.retireNotBefore, undefined);
    assert.equal(await issuer.removeSigningKey(later!), true, 'later unused keys follow ordinary zero-cache retirement');
    now = deadline - 1;
    assert.equal(await issuer.removeSigningKey(oldKey.kid), false);
    now = deadline;
    assert.equal(await issuer.removeSigningKey(oldKey.kid), true, 'ordinary retirement starts at the exact fixed boundary');
    const [replacement] = await issuer.publishSigningKeys([await privateJwk()]);
    now++;
    assert.equal(await issuer.activateSigningKey(replacement!), true);
    assert.equal(await issuer.removeSigningKey(nextKey.kid), false, 'the shorter current cache policy cannot erase a legacy issuing key\'s overlap');
    now = issuingDeadline;
    assert.equal(await issuer.removeSigningKey(nextKey.kid), true);
  });
}
