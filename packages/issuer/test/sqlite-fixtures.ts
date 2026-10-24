import type { Agent, AgentKey, Code, Store, Transaction } from '../src/store.js';

/** Valid store records: cryptographic verification belongs to the HTTP tests, before these atomic operations. */
export async function prepareAgent(store: Store, id: string): Promise<void> {
  await store.putOwner({ id: 'owner', ownerSub: 'owner-sub', email: 'owner@example.com', emailVerified: true, verifiedVia: 'passkey', createdAt: 1 });
  const agent: Agent = { handle: `${id}@example.com`, local: id, domain: 'example.com', sub: id, ownerId: 'owner', preferredUsername: id, enabled: true, authorizationVersion: 0, createdAt: 1 };
  await store.putAgent(agent);
  const credential = { hash: `credential-${id}`, ownerId: 'owner', kind: 'owner' as const, sessionAuth: 'passkey' as const, createdAt: 1 };
  await store.putCredential(credential);
  const key: AgentKey = { kid: `key-${id}`, handle: agent.handle, agentSub: id, enrollment: `enrollment-${id}`, status: 'pending', jwk: { kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y' }, permissions: { share_owner: false }, createdAt: 1, expiresAt: 100, challenge: { value: 'challenge', expiresAt: 100 } };
  if (await store.insertKey(key, 1, { ...credential, agentSub: id }) !== 'ok') throw new Error('could not prepare test enrollment');
  if (!await store.activateKey(key.kid, key.enrollment, 'challenge', 1)) throw new Error('could not activate test enrollment');
}

export async function beginSignIn(store: Store, id: string, txnId: string, clientId: string, maxSignups?: number): Promise<Transaction> {
  const tx: Transaction = {
    id: txnId, version: 0, clientId, redirectUri: 'https://rp.example/cb', scopes: ['openid'], state: 'state', nonce: 'nonce', codeChallenge: 'challenge',
    disclosure: [], clientPresentation: { type: 'registered' }, status: 'awaiting_agent', challenge: 'challenge', createdAt: 1, expiresAt: 100,
    acceptDisclosure: true, deliverToSession: false, ownerApprovalOutstanding: false, reviewOutstanding: false, passedCap: false, continueSecret: 'continue', codeIssued: false,
  };
  await store.insertTransaction(tx);
  const ready = await store.updateTransaction({ ...tx, status: 'ready', challenge: undefined, handle: `${id}@example.com`, kid: `key-${id}`, keyEnrollment: `enrollment-${id}`, agentSub: id, agentVersion: 0, accountVersion: 0, ownerId: 'owner', assertedAt: 1 }, 0, { now: 1, maxSignups });
  if (!ready) throw new Error('test transaction was unexpectedly updated concurrently');
  return ready;
}

export async function finishSignIn(store: Store, tx: Transaction): Promise<Transaction | undefined> {
  const code: Code = {
    hash: `code-${tx.id}`, txnId: tx.id, clientId: tx.clientId, redirectUri: tx.redirectUri, codeChallenge: tx.codeChallenge, nonce: tx.nonce, scopes: tx.scopes,
    handle: tx.handle!, kid: tx.kid!, keyEnrollment: tx.keyEnrollment!, agentSub: tx.agentSub!, agentVersion: tx.agentVersion!, accountVersion: tx.accountVersion!, authTime: 1,
    expiresAt: 100, used: false, voided: false,
  };
  return store.completeTransaction(tx, tx.version, code, 1);
}
