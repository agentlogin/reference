// Storage model and an in-memory implementation.
//
// The protocol's security invariants are single store operations with explicit preconditions: activating a pending
// key, revoking a key, accepting a change to a transaction, reserving a place under a per-owner cap, redeeming a
// code, recording a completed sign-in. Each must be atomic in the store, a single conditional write or one database
// transaction, because the issuer holds no locks of its own: any number of issuer processes may share one store.
// Everything else is plain reads and inserts. The in-memory store keeps and returns copies, as a database does.
import type { Scope } from './constants.js';

export type OwnerVerifiedVia = 'email' | 'oidc' | 'domain' | 'passkey';
export interface Owner {
  id: string;
  ownerSub: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  verifiedVia: OwnerVerifiedVia;
  createdAt: number;
}
export interface Agent {
  handle: string;
  local: string;
  domain: string;
  sub: string;
  ownerId: string;
  name?: string;
  preferredUsername: string;
  enabled: boolean;
  createdAt: number;
}
/**
 * How the session that issued an Owner Credential authenticated the Owner (Section 6.6): `passkey`, `oidc`, `domain`,
 * `email_factor` (email plus a factor the Agent cannot read) qualify for Owner approval and `share_owner`;
 * `email_only` (a one-time code or link alone) does not.
 */
export type SessionAuth = 'passkey' | 'oidc' | 'domain' | 'email_factor' | 'email_only';
/** Owner Credential or Delegated Credential (Section 1.2), stored hashed. */
export interface Credential {
  hash: string;
  ownerId: string;
  kind: 'owner' | 'delegated';
  handle?: string; // delegated credentials are bound to one handle
  sessionAuth?: SessionAuth; // owner credentials only
  createdAt: number;
}
/** One-time code of the Owner email sign-in (Section 7.5 `email`), stored hashed; one outstanding code per Owner. */
export interface OwnerCode {
  ownerId: string;
  hash: string;
  expiresAt: number;
}
export type KeyStatus = 'pending' | 'active' | 'revoked' | 'expired';
export interface P256Jwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }
export interface AgentKey {
  kid: string;
  handle: string;
  /**
   * Identifies this enrollment of the key. A transaction, code or Access Token is bound to the enrollment that
   * asserted it: enrolling the same public key again after it expired starts a new enrollment and revives nothing.
   */
  enrollment: string;
  status: KeyStatus;
  jwk: P256Jwk;
  permissions: { share_owner: boolean };
  name?: string;
  createdAt: number;
  expiresAt: number;
  challenge?: { value: string; expiresAt: number };
  revokedAt?: number;
}
export type AuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';
export interface Client {
  clientId: string;
  type: 'open' | 'registered';
  redirectUris: string[];
  clientName?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  initiateLoginUri?: string;
  maxSignupsPerOwner?: number;
  requireReview: boolean;
  /** Section 4.4: the Relay registering as a client; every redirect URI is on its host. */
  relayIssuer?: string;
  /** Section 4.4: the Relay's `op_policy_uri`, from its metadata as of registration (shown by the approval page, Section 6.6). */
  relayPolicyUri?: string;
  tokenEndpointAuthMethod: AuthMethod;
  clientSecretHash?: string;
  fetchedAt?: number;
  cacheUntil?: number;
}
export type TxStatus = 'awaiting_agent' | 'awaiting_owner' | 'awaiting_consent' | 'ready' | 'completed' | 'denied' | 'expired';
export const TERMINAL: ReadonlySet<TxStatus> = new Set(['completed', 'denied', 'expired']);
export type DenyReason =
  | 'cancelled' | 'access_denied' | 'key_revoked' | 'owner_declined'
  | 'consent_required' | 'interaction_required' | 'signup_limit_reached';
export type ConsentReason = 'first_visit' | 'material_change' | 'expired' | 'prompt_consent' | 'policy';
export interface Disclosure { scope: Scope; title: string; description: string }
export interface Transaction {
  id: string;
  /** Incremented by every accepted change; a change is accepted only against the version it was computed from. */
  version: number;
  clientId: string;
  redirectUri: string;
  scopes: Scope[];
  state: string;
  nonce: string;
  codeChallenge: string;
  prompt?: 'consent' | 'none';
  loginHint?: string;
  disclosure: Disclosure[];
  requester?: { user_agent?: string; network?: string };
  status: TxStatus;
  reason?: DenyReason;
  consentReason?: ConsentReason;
  challenge?: string;
  createdAt: number;
  expiresAt: number;
  terminalAt?: number;
  // set by the assertion (Section 6.3)
  handle?: string;
  kid?: string;
  /** The enrollment of `kid` that asserted (see AgentKey.enrollment). */
  keyEnrollment?: string;
  ownerId?: string;
  assertedAt?: number;
  acceptDisclosure: boolean;
  deliverToSession: boolean;
  ownerApprovalOutstanding: boolean;
  reviewOutstanding: boolean;
  /** The sign-in proceeds on the strength of an existing Consent Record; its last use is renewed when the transaction becomes ready. */
  consentRelied?: boolean;
  passedCap: boolean; // holds a reservation under the per-owner cap (Section 7.6)
  // credentials (hashed) and the continue URL secret
  transactionTokenHash?: string;
  sessionSecretHash?: string;
  /** Chosen at creation; released to a requester only as Section 6.5 allows. */
  continueSecret: string;
  codeIssued: boolean;
}
export interface Code {
  hash: string;
  txnId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  nonce: string;
  scopes: Scope[];
  handle: string;
  kid: string;
  keyEnrollment: string;
  authTime: number;
  expiresAt: number;
  used: boolean;
  voided: boolean;
  /** Presented again after it was used (Section 5.4): the tokens issued for it are revoked, whichever request notices. */
  replayed?: boolean;
}
export interface AccessToken {
  hash: string;
  txnId: string;
  clientId: string;
  handle: string;
  kid: string;
  keyEnrollment: string;
  scopes: Scope[];
  expiresAt: number;
  revoked: boolean;
}
export interface Consent {
  handle: string;
  clientId: string;
  scopes: Scope[];
  redirectHost: string;
  clientName?: string;
  tosUri?: string;
  policyUri?: string;
  createdAt: number;
  lastUsedAt: number;
}
export interface Account {
  handle: string;
  clientId: string;
  status: 'enabled' | 'disabled';
  firstSignedInAt: number;
  lastSignedInAt: number;
  signInCount: number;
}

/** Selects transactions, codes or Access Tokens by what they are bound to. Absent members match everything. */
export interface SubjectFilter { kid?: string; keyEnrollment?: string; handle?: string; clientId?: string; ownerId?: string; txnId?: string }
export type InsertKeyResult = 'ok' | 'enrolled' | 'other_handle' | 'revoked';
export type RedeemResult = 'ok' | 'used' | 'void' | 'expired' | 'unknown';

export interface Store {
  // ---- owners, agents, credentials ----
  putOwner(o: Owner): Promise<void>;
  getOwner(id: string): Promise<Owner | undefined>;
  /** The Owner with this address (compared without regard to case); the most recently created when several share it. */
  getOwnerByEmail(email: string): Promise<Owner | undefined>;
  putOwnerCode(c: OwnerCode): Promise<void>;
  /** ATOMIC. Returns and deletes the Owner's outstanding code. */
  takeOwnerCode(ownerId: string): Promise<OwnerCode | undefined>;
  putAgent(a: Agent): Promise<void>;
  getAgent(handle: string): Promise<Agent | undefined>;
  /** ATOMIC. Sets `enabled` on an existing Agent and returns it. */
  setAgentEnabled(handle: string, enabled: boolean): Promise<Agent | undefined>;
  deleteAgent(handle: string): Promise<void>;
  listAgentsByOwner(ownerId: string): Promise<Agent[]>;
  putCredential(c: Credential): Promise<void>;
  getCredential(hash: string): Promise<Credential | undefined>;
  listCredentials(filter: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }): Promise<Credential[]>;
  deleteCredential(hash: string): Promise<void>;

  // ---- keys (Section 7) ----
  getKey(kid: string): Promise<AgentKey | undefined>;
  listKeys(handle: string): Promise<AgentKey[]>;
  /**
   * ATOMIC. Stores a `pending` key unless the public key was revoked for this handle (`revoked`) or is enrolled
   * now, pending with an unexpired challenge or active and unexpired, for this handle (`enrolled`) or another
   * (`other_handle`). A dead record of the same key is replaced.
   */
  insertKey(k: AgentKey, now: number): Promise<InsertKeyResult>;
  /**
   * ATOMIC. `pending` becomes `active`, only if this enrollment is still pending and `challenge` is its unconsumed,
   * unexpired challenge. False otherwise: in particular when the key was revoked while the proof was verified.
   */
  activateKey(kid: string, enrollment: string, challenge: string, now: number): Promise<boolean>;
  /**
   * ATOMIC. A `pending` or `active` key becomes `revoked` and is remembered as revoked for its handle. Returns the
   * key when this call revoked it, nothing when there was nothing to revoke.
   */
  revokeKey(kid: string, now: number): Promise<AgentKey | undefined>;
  /** ATOMIC. Changes the label or permissions of this enrollment without touching its status. */
  patchKey(kid: string, enrollment: string, patch: { name?: string; shareOwner?: boolean }): Promise<AgentKey | undefined>;
  /** Deletes the record; with `enrollment`, only if it still is that enrollment. */
  deleteKey(kid: string, enrollment?: string): Promise<void>;
  wasRevoked(handle: string, kid: string): Promise<boolean>;

  // ---- clients ----
  putClient(c: Client): Promise<void>;
  getClient(clientId: string): Promise<Client | undefined>;

  // ---- transactions (Section 6) ----
  insertTransaction(t: Transaction): Promise<void>;
  getTransaction(id: string): Promise<Transaction | undefined>;
  /**
   * ATOMIC. Replaces the transaction only if its stored version is `expectedVersion`, and stores it with the next
   * version. False when another request changed it first: the caller re-reads and decides again.
   */
  updateTransaction(t: Transaction, expectedVersion: number): Promise<boolean>;
  /** Transactions whose stored status is not terminal (an expired one may still be listed; callers look at `expiresAt`). */
  listOpenTransactions(filter: SubjectFilter): Promise<Transaction[]>;

  // ---- codes and Access Tokens (Section 5) ----
  insertCode(c: Code): Promise<void>;
  getCode(hash: string): Promise<Code | undefined>;
  /**
   * ATOMIC. Marks the code used if it is neither used, void nor expired; otherwise says which. One redemption wins.
   * A code that was used already is also marked `replayed`.
   */
  redeemCode(hash: string, now: number): Promise<RedeemResult>;
  /** ATOMIC per code. Voids every matching code that has not been used. */
  voidCodes(filter: SubjectFilter): Promise<void>;
  insertAccessToken(t: AccessToken): Promise<void>;
  getAccessToken(hash: string): Promise<AccessToken | undefined>;
  /** ATOMIC per token. Revokes every matching Access Token. */
  revokeAccessTokens(filter: SubjectFilter): Promise<void>;

  // ---- consent (Section 6.4) ----
  getConsent(handle: string, clientId: string): Promise<Consent | undefined>;
  listConsents(handle: string): Promise<Consent[]>;
  /** ATOMIC. Creates the record or adds the scopes to it, takes the client's current values, and sets its last use. */
  grantConsent(c: Omit<Consent, 'createdAt' | 'lastUsedAt'>, now: number): Promise<void>;
  /** ATOMIC. Sets the last use of an existing record. */
  touchConsent(handle: string, clientId: string, now: number): Promise<void>;
  deleteConsent(handle: string, clientId: string): Promise<void>;

  // ---- accounts and the per-owner cap (Sections 7.4, 7.6) ----
  getAccount(handle: string, clientId: string): Promise<Account | undefined>;
  listAccounts(handle: string): Promise<Account[]>;
  /** ATOMIC. Sets the status of an existing Account and returns it. */
  setAccountStatus(handle: string, clientId: string, status: 'enabled' | 'disabled'): Promise<Account | undefined>;
  deleteAccount(handle: string, clientId: string): Promise<void>;
  /** Number of Accounts ever created for (Owner, client), including disabled and deleted ones. */
  signupsEver(ownerId: string, clientId: string): Promise<number>;
  /**
   * ATOMIC. Reserves a place under the cap for an Agent that has no Account at the client, on behalf of one
   * transaction, until `expiresAt`. Granted when the Accounts ever created plus the other Agents that hold an
   * unexpired reservation and still have no Account number fewer than `max`. An Agent's own reservations and Agents
   * that have an Account by now take no further place.
   */
  reserveSignup(p: { ownerId: string; clientId: string; handle: string; txnId: string; expiresAt: number; max: number; now: number }): Promise<boolean>;
  /** Moves the expiry of a transaction's reservation, if it holds one (a transaction waiting for the Owner lives longer). */
  extendSignup(p: { ownerId: string; clientId: string; txnId: string; expiresAt: number }): Promise<void>;
  /** Gives up a transaction's reservation, if it holds one. */
  releaseSignup(p: { ownerId: string; clientId: string; txnId: string }): Promise<void>;
  /**
   * ATOMIC. Records a completed sign-in: creates the Account and counts one sign-up for the Owner when the Account
   * does not exist, otherwise updates its counters; either way the transaction's reservation ends. However many
   * transactions complete for one Account at the same time, it is created and counted once.
   */
  recordSignIn(p: { handle: string; clientId: string; ownerId: string; txnId: string; now: number }): Promise<{ created: boolean }>;
}

const copy = <T>(v: T): T => (v === undefined ? v : structuredClone(v));
const matches = (x: { kid?: string; keyEnrollment?: string; handle?: string; clientId?: string; ownerId?: string; txnId?: string }, f: SubjectFilter): boolean =>
  (f.kid === undefined || x.kid === f.kid) &&
  (f.keyEnrollment === undefined || x.keyEnrollment === f.keyEnrollment) &&
  (f.handle === undefined || x.handle === f.handle) &&
  (f.clientId === undefined || x.clientId === f.clientId) &&
  (f.ownerId === undefined || x.ownerId === f.ownerId) &&
  (f.txnId === undefined || x.txnId === f.txnId);

/**
 * The in-memory store. Every method body runs without awaiting anything, so each is atomic within the process; it
 * stores and returns copies, so nothing a caller holds changes behind its back or changes the store by itself.
 */
export class MemoryStore implements Store {
  private owners = new Map<string, Owner>();
  private agents = new Map<string, Agent>();
  private ownerCodes = new Map<string, OwnerCode>();
  private credentials = new Map<string, Credential>();
  private keys = new Map<string, AgentKey>();
  private revoked = new Set<string>();
  private clients = new Map<string, Client>();
  private transactions = new Map<string, Transaction>();
  private codes = new Map<string, Code>();
  private tokens = new Map<string, AccessToken>();
  private consents = new Map<string, Consent>();
  private accounts = new Map<string, Account>();
  private signups = new Map<string, number>();
  private reservations = new Map<string, Map<string, { handle: string; expiresAt: number }>>();

  async putOwner(o: Owner) { this.owners.set(o.id, copy(o)); }
  async getOwner(id: string) { return copy(this.owners.get(id)); }
  async getOwnerByEmail(email: string) {
    const wanted = email.toLowerCase();
    return copy([...this.owners.values()].filter((o) => o.email.toLowerCase() === wanted).sort((a, b) => b.createdAt - a.createdAt)[0]);
  }
  async putOwnerCode(c: OwnerCode) { this.ownerCodes.set(c.ownerId, copy(c)); }
  async takeOwnerCode(ownerId: string) {
    const c = this.ownerCodes.get(ownerId);
    this.ownerCodes.delete(ownerId);
    return c;
  }
  async putAgent(a: Agent) { this.agents.set(a.handle, copy(a)); }
  async getAgent(handle: string) { return copy(this.agents.get(handle)); }
  async setAgentEnabled(handle: string, enabled: boolean) {
    const a = this.agents.get(handle);
    if (a) a.enabled = enabled;
    return copy(a);
  }
  async deleteAgent(handle: string) { this.agents.delete(handle); }
  async listAgentsByOwner(ownerId: string) { return copy([...this.agents.values()].filter((a) => a.ownerId === ownerId)); }
  async putCredential(c: Credential) { this.credentials.set(c.hash, copy(c)); }
  async getCredential(hash: string) { return copy(this.credentials.get(hash)); }
  async listCredentials(f: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }) {
    return copy([...this.credentials.values()].filter((c) => (f.ownerId === undefined || c.ownerId === f.ownerId) && (f.handle === undefined || c.handle === f.handle) && (f.kind === undefined || c.kind === f.kind)));
  }
  async deleteCredential(hash: string) { this.credentials.delete(hash); }

  async getKey(kid: string) { return copy(this.keys.get(kid)); }
  async listKeys(handle: string) { return copy([...this.keys.values()].filter((k) => k.handle === handle)); }
  async insertKey(k: AgentKey, now: number): Promise<InsertKeyResult> {
    if (this.revoked.has(`${k.handle}\u0000${k.kid}`)) return 'revoked';
    const cur = this.keys.get(k.kid);
    const enrolled = cur !== undefined && ((cur.status === 'pending' && cur.challenge !== undefined && now <= cur.challenge.expiresAt) || (cur.status === 'active' && now < cur.expiresAt));
    if (enrolled) return cur.handle === k.handle ? 'enrolled' : 'other_handle';
    this.keys.set(k.kid, copy(k));
    return 'ok';
  }
  async activateKey(kid: string, enrollment: string, challenge: string, now: number) {
    const k = this.keys.get(kid);
    if (!k || k.enrollment !== enrollment || k.status !== 'pending' || !k.challenge || k.challenge.value !== challenge || now > k.challenge.expiresAt) return false;
    k.status = 'active';
    k.challenge = undefined;
    return true;
  }
  async revokeKey(kid: string, now: number) {
    const k = this.keys.get(kid);
    if (!k || (k.status !== 'pending' && k.status !== 'active')) return undefined;
    k.status = 'revoked';
    k.revokedAt = now;
    k.challenge = undefined;
    this.revoked.add(`${k.handle}\u0000${k.kid}`);
    return copy(k);
  }
  async patchKey(kid: string, enrollment: string, patch: { name?: string; shareOwner?: boolean }) {
    const k = this.keys.get(kid);
    if (!k || k.enrollment !== enrollment) return undefined;
    if (patch.name !== undefined) k.name = patch.name;
    if (patch.shareOwner !== undefined) k.permissions.share_owner = patch.shareOwner;
    return copy(k);
  }
  async deleteKey(kid: string, enrollment?: string) {
    const k = this.keys.get(kid);
    if (k && (enrollment === undefined || k.enrollment === enrollment)) this.keys.delete(kid);
  }
  async wasRevoked(handle: string, kid: string) { return this.revoked.has(`${handle}\u0000${kid}`); }

  async putClient(c: Client) { this.clients.set(c.clientId, copy(c)); }
  async getClient(clientId: string) { return copy(this.clients.get(clientId)); }

  async insertTransaction(t: Transaction) { this.transactions.set(t.id, copy(t)); }
  async getTransaction(id: string) { return copy(this.transactions.get(id)); }
  async updateTransaction(t: Transaction, expectedVersion: number) {
    const cur = this.transactions.get(t.id);
    if (!cur || cur.version !== expectedVersion) return false;
    this.transactions.set(t.id, { ...copy(t), version: expectedVersion + 1 });
    return true;
  }
  async listOpenTransactions(f: SubjectFilter) {
    return copy([...this.transactions.values()].filter((t) => !TERMINAL.has(t.status) && matches({ ...t, txnId: t.id }, f)));
  }

  async insertCode(c: Code) { this.codes.set(c.hash, copy(c)); }
  async getCode(hash: string) { return copy(this.codes.get(hash)); }
  async redeemCode(hash: string, now: number): Promise<RedeemResult> {
    const c = this.codes.get(hash);
    if (!c) return 'unknown';
    if (c.used) {
      c.replayed = true;
      return 'used';
    }
    if (c.voided) return 'void';
    if (now >= c.expiresAt) return 'expired';
    c.used = true;
    return 'ok';
  }
  async voidCodes(f: SubjectFilter) { for (const c of this.codes.values()) if (!c.used && matches(c, f)) c.voided = true; }
  async insertAccessToken(t: AccessToken) { this.tokens.set(t.hash, copy(t)); }
  async getAccessToken(hash: string) { return copy(this.tokens.get(hash)); }
  async revokeAccessTokens(f: SubjectFilter) { for (const t of this.tokens.values()) if (matches(t, f)) t.revoked = true; }

  async getConsent(handle: string, clientId: string) { return copy(this.consents.get(`${handle}\u0000${clientId}`)); }
  async listConsents(handle: string) { return copy([...this.consents.values()].filter((c) => c.handle === handle)); }
  async grantConsent(c: Omit<Consent, 'createdAt' | 'lastUsedAt'>, now: number) {
    const key = `${c.handle}\u0000${c.clientId}`;
    const cur = this.consents.get(key);
    this.consents.set(key, { ...copy(c), scopes: [...new Set([...(cur?.scopes ?? []), ...c.scopes])], createdAt: cur?.createdAt ?? now, lastUsedAt: now });
  }
  async touchConsent(handle: string, clientId: string, now: number) {
    const cur = this.consents.get(`${handle}\u0000${clientId}`);
    if (cur) cur.lastUsedAt = now;
  }
  async deleteConsent(handle: string, clientId: string) { this.consents.delete(`${handle}\u0000${clientId}`); }

  async getAccount(handle: string, clientId: string) { return copy(this.accounts.get(`${handle}\u0000${clientId}`)); }
  async listAccounts(handle: string) { return copy([...this.accounts.values()].filter((a) => a.handle === handle)); }
  async setAccountStatus(handle: string, clientId: string, status: 'enabled' | 'disabled') {
    const a = this.accounts.get(`${handle}\u0000${clientId}`);
    if (a) a.status = status;
    return copy(a);
  }
  async deleteAccount(handle: string, clientId: string) { this.accounts.delete(`${handle}\u0000${clientId}`); }
  async signupsEver(ownerId: string, clientId: string) { return this.signups.get(`${ownerId}\u0000${clientId}`) ?? 0; }
  async reserveSignup(p: { ownerId: string; clientId: string; handle: string; txnId: string; expiresAt: number; max: number; now: number }) {
    const key = `${p.ownerId}\u0000${p.clientId}`;
    const held = this.reservations.get(key) ?? new Map<string, { handle: string; expiresAt: number }>();
    for (const [txn, r] of held) if (r.expiresAt <= p.now) held.delete(txn); // an expired transaction holds no place
    const others = new Set<string>();
    for (const r of held.values()) if (r.handle !== p.handle && !this.accounts.has(`${r.handle}\u0000${p.clientId}`)) others.add(r.handle);
    const admitted = (this.signups.get(key) ?? 0) + others.size < p.max;
    if (admitted) held.set(p.txnId, { handle: p.handle, expiresAt: p.expiresAt });
    this.reservations.set(key, held);
    return admitted;
  }
  async extendSignup(p: { ownerId: string; clientId: string; txnId: string; expiresAt: number }) {
    const r = this.reservations.get(`${p.ownerId}\u0000${p.clientId}`)?.get(p.txnId);
    if (r) r.expiresAt = p.expiresAt;
  }
  async releaseSignup(p: { ownerId: string; clientId: string; txnId: string }) {
    this.reservations.get(`${p.ownerId}\u0000${p.clientId}`)?.delete(p.txnId);
  }
  async recordSignIn(p: { handle: string; clientId: string; ownerId: string; txnId: string; now: number }) {
    const key = `${p.ownerId}\u0000${p.clientId}`;
    this.reservations.get(key)?.delete(p.txnId);
    const accountKey = `${p.handle}\u0000${p.clientId}`;
    const existing = this.accounts.get(accountKey);
    if (existing) {
      existing.lastSignedInAt = p.now;
      existing.signInCount += 1;
      return { created: false };
    }
    this.accounts.set(accountKey, { handle: p.handle, clientId: p.clientId, status: 'enabled', firstSignedInAt: p.now, lastSignedInAt: p.now, signInCount: 1 });
    this.signups.set(key, (this.signups.get(key) ?? 0) + 1);
    return { created: true };
  }
}
