// One behavioral contract for local state machines and database adapters. Database-specific transaction barriers,
// rollback/recovery failures and process tests supplement this suite; they must not replace it.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test, type TestContext } from 'node:test';
import {
  isAssertionWindowError, type AccessToken, type Agent, type AgentKey, type Client, type Code,
  type ManagementAuthorization, type Owner, type Store, type Transaction, type TransitionEffects,
} from '../src/store.js';

export interface StoreContractFixture {
  store: Store;
  /** A second connection to the same database, or the same MemoryStore. */
  peer: Store;
  now(): number;
  /** Advance the adapter's authoritative test clock before resolving. */
  advance(seconds: number): Promise<void>;
  close?(): void | Promise<void>;
}
export type StoreContractFactory = (t: TestContext) => Promise<StoreContractFixture>;

const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

async function subject(f: StoreContractFixture, label = 'first', ownerId = 'owner') {
  const now = f.now();
  const owner: Owner = { id: ownerId, ownerSub: `sub-${ownerId}`, email: `${ownerId}@example.test`, emailVerified: true,
    verifiedVia: 'passkey', createdAt: now };
  await f.store.putOwner(owner);
  const agent: Agent = { handle: `${label}@example.test`, local: label, domain: 'example.test', sub: `identity-${label}`,
    ownerId, preferredUsername: label, enabled: true, authorizationVersion: 0, createdAt: now };
  assert.equal(await f.store.putAgent(agent), true);
  const authorization: ManagementAuthorization = { hash: hash(`credential-${label}`), ownerId, kind: 'owner',
    sessionAuth: 'passkey', agentSub: agent.sub, createdAt: now };
  await f.store.putCredential(authorization);
  const pending: AgentKey = { kid: hash(`key-${label}`), enrollment: `enrollment-${label}`, agentSub: agent.sub,
    handle: agent.handle, status: 'pending', permissions: { share_owner: false }, createdAt: now, expiresAt: now + 3600,
    challenge: { value: `challenge-${label}`, expiresAt: now + 60 }, jwk: { kty: 'EC', crv: 'P-256', x: hash(`x-${label}`), y: hash(`y-${label}`) } };
  assert.equal(await f.store.insertKey(pending, now, authorization), 'ok');
  assert.equal(await f.store.activateKey(pending.kid, pending.enrollment, pending.challenge!.value, now), true);
  return { owner, agent, authorization, key: (await f.store.getKey(pending.kid))! };
}

type Subject = Awaited<ReturnType<typeof subject>>;
async function client(f: StoreContractFixture, maxSignups = 1): Promise<Client> {
  const record: Client = { clientId: 'client', type: 'registered', redirectUris: ['https://rp.example/cb'],
    tokenEndpointAuthMethod: 'none', requireReview: false, maxSignupsPerOwner: maxSignups };
  await f.store.putClient(record);
  return record;
}

async function pending(f: StoreContractFixture, c: Client, id: string, ttl = 300): Promise<Transaction> {
  const tx: Transaction = { id, version: 0, clientId: c.clientId, redirectUri: c.redirectUris[0]!, scopes: ['openid'],
    state: `state-${id}`, nonce: `nonce-${id}`, codeChallenge: hash(`pkce-${id}`), disclosure: [], status: 'awaiting_agent',
    challenge: `challenge-${id}`, createdAt: f.now(), expiresAt: f.now() + ttl, acceptDisclosure: false,
    deliverToSession: false, ownerApprovalOutstanding: false, reviewOutstanding: false, passedCap: false,
    sessionSecretHash: hash(`session-${id}`), continueSecret: `continue-${id}`, codeIssued: false };
  await f.store.insertTransaction(tx);
  return tx;
}

function asserted(f: StoreContractFixture, tx: Transaction, s: Subject): Transaction {
  return { ...tx, status: 'ready', challenge: undefined, handle: s.agent.handle, kid: s.key.kid,
    keyEnrollment: s.key.enrollment, agentSub: s.agent.sub, agentVersion: s.agent.authorizationVersion,
    accountVersion: 0, ownerId: s.owner.id, assertedAt: f.now(), transactionTokenHash: hash(`assertion-${tx.id}`) };
}

async function ready(f: StoreContractFixture, c: Client, s: Subject, id: string, effects: Partial<TransitionEffects> = {}) {
  const tx = await pending(f, c, id);
  const accepted = await f.store.updateTransaction(asserted(f, tx, s), tx.version, { now: f.now(), maxSignups: c.maxSignupsPerOwner, ...effects });
  assert.ok(accepted);
  return accepted;
}

function codeFor(f: StoreContractFixture, tx: Transaction, suffix = ''): Code {
  return { hash: hash(`code-${tx.id}${suffix}`), txnId: tx.id, clientId: tx.clientId, redirectUri: tx.redirectUri,
    codeChallenge: tx.codeChallenge, nonce: tx.nonce, scopes: tx.scopes, handle: tx.handle!, kid: tx.kid!,
    keyEnrollment: tx.keyEnrollment!, agentSub: tx.agentSub!, agentVersion: tx.agentVersion!, accountVersion: tx.accountVersion!,
    authTime: tx.assertedAt!, expiresAt: f.now() + 60, used: false, voided: false };
}

async function complete(f: StoreContractFixture, tx: Transaction) {
  const code = codeFor(f, tx);
  const result = await f.store.completeTransaction({ ...tx, status: 'completed', codeIssued: true }, tx.version, code, f.now());
  assert.equal(result?.status, 'completed');
  return code;
}

function tokenFor(f: StoreContractFixture, code: Code, label = 'token'): AccessToken {
  return { hash: hash(label), txnId: code.txnId, clientId: code.clientId, handle: code.handle, kid: code.kid,
    keyEnrollment: code.keyEnrollment, agentSub: code.agentSub, agentVersion: code.agentVersion,
    accountVersion: code.accountVersion, scopes: code.scopes, expiresAt: f.now() + 600, revoked: false };
}

export function registerStoreContract(name: string, factory: StoreContractFactory): void {
  const check = (description: string, run: (f: StoreContractFixture) => Promise<void>) => {
    test(`${name} store contract: ${description}`, async (t) => {
      const f = await factory(t);
      if (f.close) t.after(() => f.close!());
      await run(f);
    });
  };

  check('records are copied and handle identity cannot be overwritten or reused by stale authorization', async (f) => {
    const s = await subject(f);
    const owner = (await f.peer.getOwner(s.owner.id))!;
    owner.email = 'changed@example.test';
    assert.equal((await f.store.getOwner(s.owner.id))?.email, s.owner.email);
    assert.equal(await f.peer.putAgent({ ...s.agent, sub: 'replacement' }), false);
    assert.equal(await f.peer.deleteAgent(s.agent.handle, 'wrong-identity', f.now()), false);
    assert.equal(await f.peer.deleteAgent(s.agent.handle, s.agent.sub, f.now()), true);
    assert.equal(await f.peer.putAgent({ ...s.agent, sub: 'replacement' }), true);
    assert.equal(await f.store.insertKey({ ...s.key, kid: hash('fresh-key'), enrollment: 'fresh-enrollment' }, f.now(), s.authorization), 'unauthorized');
    assert.equal((await f.store.getAgent(s.agent.handle))?.sub, 'replacement');
  });

  check('immutable subjects and transaction IDs cannot be reused to overwrite existing identities', async (f) => {
    const a = await subject(f); const c = await client(f);
    await assert.rejects(f.peer.putOwner({ ...a.owner, ownerSub: 'changed-owner-subject' }));
    assert.equal((await f.store.getOwner(a.owner.id))?.ownerSub, a.owner.ownerSub);
    assert.equal(await f.peer.putAgent({ ...a.agent, handle: 'other@example.test', local: 'other' }), false);
    const tx = await pending(f, c, 'unique-transaction');
    await assert.rejects(f.peer.insertTransaction({ ...tx, nonce: 'replacement-nonce' }));
    assert.equal((await f.store.getTransaction(tx.id))?.nonce, tx.nonce);
  });

  check('one current key enrollment belongs to one agent and a stale revocation cannot affect its replacement', async (f) => {
    const a = await subject(f);
    const b = await subject(f, 'second');
    const replacement: AgentKey = { ...a.key, handle: b.agent.handle, agentSub: b.agent.sub, enrollment: 'new-enrollment',
      status: 'pending', challenge: { value: 'proof', expiresAt: f.now() + 60 }, expiresAt: f.now() + 7200 };
    assert.equal(await f.peer.insertKey(replacement, f.now(), b.authorization), 'other_handle');
    await f.advance(3601);
    replacement.challenge!.expiresAt = f.now() + 60;
    assert.equal(await f.peer.insertKey(replacement, f.now(), b.authorization), 'ok');
    assert.equal(await f.store.revokeKey(a.key.kid, a.key.enrollment, f.now()), undefined);
    assert.equal(await f.peer.activateKey(replacement.kid, replacement.enrollment, 'proof', f.now()), true);
    assert.equal((await f.store.getKey(a.key.kid))?.enrollment, replacement.enrollment);
    assert.equal((await f.store.getKey(a.key.kid))?.status, 'active');
  });

  check('duplicate assertions own no cleanup and concurrent transactions for one agent consume one quota place', async (f) => {
    const a = await subject(f); const b = await subject(f, 'second'); const c = await client(f);
    const initial = await pending(f, c, 'one');
    const attempt = asserted(f, initial, a);
    const results = await Promise.all([f.store, f.peer].map((store) => store.updateTransaction(attempt, 0, { now: f.now(), maxSignups: 1 })));
    assert.equal(results.filter(Boolean).length, 1);
    const accepted = results.find(Boolean)!;
    const sibling = await ready(f, c, a, 'two');
    assert.equal(sibling.status, 'ready');
    const refused = await ready(f, c, b, 'three');
    assert.equal(refused.reason, 'signup_limit_reached');
    const code = await complete(f, accepted);
    const duplicateCode = codeFor(f, accepted, '-duplicate');
    assert.equal(await f.peer.completeTransaction(accepted, accepted.version, duplicateCode, f.now()), undefined);
    assert.equal(await f.store.getCode(duplicateCode.hash), undefined);
    assert.equal((await f.peer.getCode(code.hash))?.txnId, accepted.id);
    await complete(f, sibling);
    assert.equal(await f.store.signupsEver(a.owner.id, c.clientId), 1);
    assert.equal((await f.store.getAccount(a.agent.handle, c.clientId))?.signInCount, 2);
    assert.equal(await f.store.getAccount(b.agent.handle, c.clientId), undefined);
  });

  check('terminal decisions and expired reservations release quota without requiring a polling write', async (f) => {
    const a = await subject(f); const b = await subject(f, 'second'); const c = await client(f);
    const first = await ready(f, c, a, 'first');
    assert.equal((await f.store.updateTransaction({ ...first, status: 'denied', reason: 'cancelled', terminalAt: f.now() }, first.version, { now: f.now() }))?.status, 'denied');
    const second = await ready(f, c, b, 'second');
    assert.equal(second.status, 'ready');
    await f.advance(301);
    const third = await ready(f, c, a, 'third');
    assert.equal(third.status, 'ready');
    assert.equal((await f.store.getTransaction(second.id))?.status, 'ready', 'admission does not need polling to persist expiry');
    await complete(f, third);
    assert.equal(await f.store.signupsEver(a.owner.id, c.clientId), 1);
  });

  check('code bindings come from the accepted transaction and a code-hash collision rolls completion back', async (f) => {
    const a = await subject(f); const c = await client(f);
    const first = await ready(f, c, a, 'first-code');
    const firstCode = codeFor(f, first);
    assert.equal((await f.store.completeTransaction(first, first.version,
      { ...firstCode, agentVersion: 999, scopes: ['openid', 'owner_email'] }, f.now()))?.status, 'completed');
    assert.equal((await f.peer.getCode(firstCode.hash))?.agentVersion, first.agentVersion);
    assert.deepEqual((await f.peer.getCode(firstCode.hash))?.scopes, first.scopes);
    const second = await ready(f, c, a, 'second-code');
    const beforeCollision = await f.store.getTransaction(second.id);
    await assert.rejects(f.peer.completeTransaction(second, second.version, { ...codeFor(f, second), hash: firstCode.hash }, f.now()));
    assert.deepEqual(await f.store.getTransaction(second.id), beforeCollision);
    assert.equal((await f.store.getCode(firstCode.hash))?.txnId, first.id);
    assert.equal((await f.store.getAccount(a.agent.handle, c.clientId))?.signInCount, 1);
    assert.equal(await f.store.signupsEver(a.owner.id, c.clientId), 1);
    await complete(f, second);
    assert.equal((await f.store.getAccount(a.agent.handle, c.clientId))?.signInCount, 2);
  });

  check('disable and re-enable fences stale assertions and codes, retaining permanent signup accounting', async (f) => {
    const a = await subject(f); const c = await client(f);
    const tx = await ready(f, c, a, 'completed'); const code = await complete(f, tx);
    const stale = await pending(f, c, 'stale');
    await f.peer.setAgentEnabled(a.agent.handle, false, a.agent.sub, f.now());
    await f.peer.setAgentEnabled(a.agent.handle, true, a.agent.sub, f.now());
    const denied = await f.store.updateTransaction(asserted(f, stale, a), stale.version, { now: f.now(), maxSignups: 1 });
    assert.equal(denied?.reason, 'access_denied');
    assert.equal(await f.store.redeemCode(code.hash, f.now()), 'void');
    assert.equal((await f.store.getAgent(a.agent.handle))?.authorizationVersion, 1);
    await f.store.deleteAgent(a.agent.handle, a.agent.sub, f.now());
    assert.equal(await f.store.signupsEver(a.owner.id, c.clientId), 1);
  });

  check('account disable versions survive re-enable and invalidate previously issued credentials', async (f) => {
    const a = await subject(f); const c = await client(f);
    const tx = await ready(f, c, a, 'account'); const code = await complete(f, tx);
    assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
    const token = tokenFor(f, code);
    assert.equal(await f.store.insertAccessToken(token, f.now()), true);
    await f.peer.setAccountStatus(a.agent.handle, c.clientId, 'disabled', a.authorization, f.now());
    await f.peer.setAccountStatus(a.agent.handle, c.clientId, 'enabled', a.authorization, f.now());
    assert.equal((await f.store.getAccount(a.agent.handle, c.clientId))?.authorizationVersion, 1);
    assert.equal((await f.store.getAccessToken(token.hash))?.revoked, true);
    assert.equal(await f.store.insertAccessToken(tokenFor(f, code, 'late-token'), f.now()), false);
    assert.equal(await f.store.signupsEver(a.owner.id, c.clientId), 1);
  });

  check('a token must retain the redeemed code scopes and lifecycle bindings', async (f) => {
    const a = await subject(f); const c = await client(f);
    const code = await complete(f, await ready(f, c, a, 'token-binding'));
    assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
    const elevated = { ...tokenFor(f, code, 'elevated-scopes'), scopes: ['openid', 'owner_email'] as AccessToken['scopes'] };
    assert.equal(await f.peer.insertAccessToken(elevated, f.now()), false, 'candidate scopes cannot expand the authorization code');
    await f.store.setAgentEnabled(a.agent.handle, false, a.agent.sub, f.now());
    const updated = await f.store.setAgentEnabled(a.agent.handle, true, a.agent.sub, f.now());
    const rebound = { ...tokenFor(f, code, 'rebound-token'), agentVersion: updated!.authorizationVersion };
    assert.equal(await f.peer.insertAccessToken(rebound, f.now()), false, 'a fresh candidate version cannot revive an old code');
    assert.equal(await f.store.getAccessToken(rebound.hash), undefined);
  });

  check('scope unions require identical material consent terms', async (f) => {
    const a = await subject(f); const c = await client(f);
    const consent = { handle: a.agent.handle, clientId: c.clientId, scopes: ['openid', 'owner_email'] as const,
      redirectHost: 'rp.example', clientName: 'RP', policyUri: 'https://rp.example/policy-a' };
    await ready(f, c, a, 'consent-a', { consent: { ...consent, scopes: [...consent.scopes] } });
    await ready(f, c, a, 'consent-same', { consent: { ...consent, scopes: ['openid'] } });
    assert.deepEqual((await f.peer.getConsent(a.agent.handle, c.clientId))?.scopes, ['openid', 'owner_email']);
    await f.advance(1);
    await ready(f, c, a, 'consent-b', { consent: { ...consent, scopes: ['openid'], policyUri: 'https://rp.example/policy-b' } });
    assert.deepEqual((await f.peer.getConsent(a.agent.handle, c.clientId))?.scopes, ['openid']);
    assert.equal((await f.store.getConsent(a.agent.handle, c.clientId))?.createdAt, f.now());
  });

  for (const change of ['missing', 'expired', 'material change', 'expired prompt none'] as const) {
    check(`consent reliance is revalidated at acceptance after ${change}`, async (f) => {
      const a = await subject(f); const c = await client(f);
      const consentContext = { handle: a.agent.handle, clientId: c.clientId, scopes: ['openid'] as Transaction['scopes'],
        redirectHost: 'rp.example', policyUri: 'https://rp.example/policy-a' };
      await ready(f, c, a, 'original-consent', { consent: consentContext });
      const tx = await pending(f, c, 'relying-assertion');
      if (change === 'missing') await f.peer.deleteConsent(a.agent.handle, c.clientId, a.authorization);
      else if (change === 'material change') await ready(f, c, a, 'changed-consent', {
        consent: { ...consentContext, policyUri: 'https://rp.example/policy-b' },
      });
      else await f.advance(11);
      const previous = await f.store.getConsent(a.agent.handle, c.clientId);
      await f.advance(1);
      const next = { ...asserted(f, tx, a), consentRelied: true, ...(change === 'expired prompt none' ? { prompt: 'none' as const } : {}) };
      const accepted = await f.store.updateTransaction(next, tx.version, { now: f.now(), maxSignups: 1,
        touchConsent: true, consentContext, expireConsentBefore: f.now() - 10 });
      if (change === 'expired prompt none') {
        assert.equal(accepted?.status, 'denied');
        assert.equal(accepted?.reason, 'consent_required');
      } else {
        assert.equal(accepted?.status, 'awaiting_consent');
        assert.equal(accepted?.consentReason, change === 'missing' ? 'first_visit' : change === 'material change' ? 'material_change' : 'expired');
      }
      assert.equal(accepted?.consentRelied, false);
      const after = await f.store.getConsent(a.agent.handle, c.clientId);
      if (after) assert.equal(after.lastUsedAt, previous?.lastUsedAt, 'stale reliance cannot renew the consent record');
    });
  }

  check('signed assertion expiry is checked at acceptance without consuming its challenge or quota', async (f) => {
    const a = await subject(f); const b = await subject(f, 'second'); const c = await client(f);
    const tx = await pending(f, c, 'assertion-window'); const next = asserted(f, tx, a);
    const expiresAt = f.now() + 5;
    await f.advance(5);
    await assert.rejects(f.store.updateTransaction(next, tx.version, { now: f.now(), maxSignups: 1,
      assertionWindow: { notBefore: expiresAt - 60, expiresAt } }), isAssertionWindowError);
    assert.deepEqual(await f.peer.getTransaction(tx.id), tx);
    assert.equal((await ready(f, c, b, 'fresh-assertion')).status, 'ready');
  });

  check('signed proof expiry is checked atomically without consuming a still-live enrollment challenge', async (f) => {
    const a = await subject(f);
    const pending: AgentKey = { ...a.key, kid: hash('pending-proof'), enrollment: 'pending-proof', status: 'pending',
      challenge: { value: 'proof-challenge', expiresAt: f.now() + 60 } };
    assert.equal(await f.store.insertKey(pending, f.now(), a.authorization), 'ok');
    const expiresAt = f.now() + 5;
    await f.advance(5);
    await assert.rejects(f.peer.activateKey(pending.kid, pending.enrollment, pending.challenge!.value, f.now(),
      { notBefore: expiresAt - 60, expiresAt }), isAssertionWindowError);
    assert.equal((await f.store.getKey(pending.kid))?.status, 'pending');
    assert.equal((await f.store.getKey(pending.kid))?.challenge?.value, pending.challenge!.value);
    assert.equal(await f.store.activateKey(pending.kid, pending.enrollment, pending.challenge!.value, f.now(),
      { notBefore: f.now() - 1, expiresAt: f.now() + 5 }), true);
  });

  check('key expiry frees its reservation during admission even without polling or cleanup', async (f) => {
    const a = await subject(f); const c = await client(f);
    const tx = await pending(f, c, 'expired-reservation-key', 7200);
    await f.store.updateTransaction(asserted(f, tx, a), tx.version, { now: f.now(), maxSignups: 1 });
    await f.advance(3601);
    const b = await subject(f, 'second');
    assert.equal((await ready(f, c, b, 'key-expiry-admission')).status, 'ready');
    assert.equal((await f.store.getTransaction(tx.id))?.status, 'ready', 'admission uses lifecycle state without requiring a materialized denial');
  });

  check('polling computes expiry without writes and later revocation cannot restart retention', async (f) => {
    const a = await subject(f); const c = await client(f); const tx = await ready(f, c, a, 'expiry');
    const beforeRead = await f.store.getTransaction(tx.id);
    await f.advance(305);
    const read = () => f.peer.readTransaction(tx.id, { now: f.now(), retainFor: 30 });
    const effective = await read();
    assert.equal(effective?.status, 'expired');
    assert.equal(effective?.terminalAt, tx.expiresAt);
    assert.deepEqual(await f.store.getTransaction(tx.id), beforeRead, 'polling must not update transaction state');
    await f.store.revokeKey(a.key.kid, a.key.enrollment, f.now());
    assert.equal((await f.store.getTransaction(tx.id))?.terminalAt, tx.expiresAt);
    await f.advance(25);
    assert.ok(await read(), 'the retention boundary remains readable');
    await f.advance(1);
    assert.equal(await read(), undefined);
  });

  check('key expiry polling is read-only and replacing that enrollment preserves its original terminal time', async (f) => {
    const a = await subject(f); const c = await client(f);
    const tx = await pending(f, c, 'key-expiry', 7200);
    await f.store.updateTransaction(asserted(f, tx, a), tx.version, { now: f.now(), maxSignups: 1 });
    const beforeRead = await f.store.getTransaction(tx.id);
    await f.advance(3601);
    const effective = await f.peer.readTransaction(tx.id, { now: f.now(), retainFor: 30 });
    assert.equal(effective?.status, 'denied');
    assert.equal(effective?.reason, 'key_revoked');
    assert.equal(effective?.terminalAt, a.key.expiresAt);
    assert.deepEqual(await f.store.getTransaction(tx.id), beforeRead);
    const replacement: AgentKey = { ...a.key, enrollment: 'after-expiry', status: 'pending', createdAt: f.now(), expiresAt: f.now() + 3600,
      challenge: { value: 'new-proof', expiresAt: f.now() + 60 } };
    assert.equal(await f.peer.insertKey(replacement, f.now(), a.authorization), 'ok');
    assert.equal((await f.store.getTransaction(tx.id))?.terminalAt, a.key.expiresAt);
    await f.advance(30);
    assert.equal(await f.store.readTransaction(tx.id, { now: f.now(), retainFor: 30 }), undefined);
  });

  for (const change of ['revocation', 'agent disable'] as const) {
    check(`${change} cannot restore visibility after a key expiry ended transaction retention`, async (f) => {
      const a = await subject(f); const c = await client(f);
      const tx = await pending(f, c, 'expired-key-retention', 7200);
      await f.store.updateTransaction(asserted(f, tx, a), tx.version, { now: f.now(), maxSignups: 1 });
      await f.advance(3631);
      assert.equal(await f.peer.readTransaction(tx.id, { now: f.now(), retainFor: 30 }), undefined);
      if (change === 'revocation') await f.store.revokeKey(a.key.kid, a.key.enrollment, f.now());
      else await f.store.setAgentEnabled(a.agent.handle, false, a.agent.sub, f.now());
      assert.equal((await f.store.getTransaction(tx.id))?.terminalAt, a.key.expiresAt);
      assert.equal((await f.store.getTransaction(tx.id))?.reason, 'key_revoked');
      assert.equal(await f.peer.readTransaction(tx.id, { now: f.now(), retainFor: 30 }), undefined);
    });
  }

  check('used-code replay atomically revokes tokens and forbids delayed issuance', async (f) => {
    const a = await subject(f); const c = await client(f);
    const code = await complete(f, await ready(f, c, a, 'replay'));
    assert.equal(await f.store.redeemCode(code.hash, f.now()), 'ok');
    const token = tokenFor(f, code);
    assert.equal(await f.store.insertAccessToken(token, f.now()), true);
    assert.equal((await f.peer.getAccessToken(token.hash))?.issuedAt, f.now());
    assert.equal((await f.peer.getAccessToken(token.hash))?.expiresAt, f.now() + 600);
    await f.advance(61); // replay evidence outlives the code's redemption expiry
    assert.equal(await f.peer.redeemCode(code.hash, f.now()), 'used');
    assert.equal((await f.store.getCode(code.hash))?.replayed, true);
    assert.equal((await f.store.getAccessToken(token.hash))?.revoked, true);
    assert.equal(await f.store.insertAccessToken(tokenFor(f, code, 'after-replay'), f.now()), false);
  });
}
