// Atomic protocol state transitions. MemoryStore and SQLiteStore share the synchronous state machine below.
// Authorization plus enrollment; assertion plus cap reservation and consent; completion plus code, Account and
// count; and lifecycle changes plus invalidation each commit together. No network or cryptographic work runs
// inside a store operation. Immutable Agent identities and persistent disable versions fence delayed work.
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
  /** Monotonic invalidation fence: disabling and re-enabling never revives old authorizations. */
  authorizationVersion: number;
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
  /** Immutable Agent identity that authorized this enrollment. */
  agentSub: string;
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
  agentSub?: string;
  agentVersion?: number;
  accountVersion?: number;
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
  agentSub: string;
  agentVersion: number;
  accountVersion: number;
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
  agentSub: string;
  agentVersion: number;
  accountVersion: number;
  scopes: Scope[];
  /** The store's clock when issuance was accepted. Older persisted snapshots may omit this field. */
  issuedAt?: number;
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
type ConsentMetadata = Pick<Consent, 'redirectHost' | 'clientName' | 'tosUri' | 'policyUri'>;
/** Section 6.4: scopes may accumulate only under the same material disclosure terms. */
export function sameConsentMetadata(a: ConsentMetadata, b: ConsentMetadata): boolean {
  return a.redirectHost === b.redirectHost && a.clientName === b.clientName && a.tosUri === b.tosUri && a.policyUri === b.policyUri;
}
/** The material consent preconditions, shared by gate planning and atomic acceptance. */
export function consentRecordReason(record: Consent | undefined,
  expected: ConsentMetadata & Pick<Consent, 'scopes'>, expireBefore?: number): 'first_visit' | 'material_change' | 'expired' | undefined {
  if (!record) return 'first_visit';
  if (!expected.scopes.every((scope) => record.scopes.includes(scope)) || !sameConsentMetadata(record, expected)) return 'material_change';
  if (expireBefore !== undefined && record.lastUsedAt < expireBefore) return 'expired';
  return undefined;
}
export interface Account {
  handle: string;
  clientId: string;
  status: 'enabled' | 'disabled';
  authorizationVersion: number;
  firstSignedInAt: number;
  lastSignedInAt: number;
  signInCount: number;
}

/** Selects transactions, codes or Access Tokens by what they are bound to. Absent members match everything. */
export interface SubjectFilter { kid?: string; keyEnrollment?: string; handle?: string; clientId?: string; ownerId?: string; txnId?: string }
export type InsertKeyResult = 'unauthorized' | 'ok' | 'enrolled' | 'other_handle' | 'revoked';
export type RedeemResult = 'ok' | 'used' | 'void' | 'expired' | 'unknown';

export interface ManagementAuthorization extends Credential { agentSub: string }
export interface TransitionEffects {
  now: number;
  /** Already verified signed assertion window, rechecked by the store at its atomic acceptance point. */
  assertionWindow?: { notBefore: number; expiresAt: number };
  maxSignups?: number;
  consent?: Omit<Consent, 'createdAt' | 'lastUsedAt'>;
  /** The disclosure whose existing consent a transition relies on; revalidated atomically before acceptance. */
  consentContext?: Omit<Consent, 'createdAt' | 'lastUsedAt'>;
  touchConsent?: boolean;
  expireConsentBefore?: number;
}
export class AssertionWindowError extends Error {
  readonly code = 'ASSERTION_WINDOW';
  constructor() { super('The signed assertion is outside its validity window'); this.name = 'AssertionWindowError'; }
}
/** Stable across separate copies of this package loaded by an external adapter. */
export function isAssertionWindowError(error: unknown): error is AssertionWindowError {
  return error instanceof Error && 'code' in error && error.code === 'ASSERTION_WINDOW';
}
/** The public key is already active for another Agent; pending enrollments confer no exclusivity. */
export class KeyActivationConflictError extends Error {
  readonly code = 'KEY_ACTIVATION_CONFLICT';
  constructor() { super('The public key is active for another Agent'); this.name = 'KeyActivationConflictError'; }
}
/** Stable across separate copies of this package loaded by an external adapter. */
export function isKeyActivationConflictError(error: unknown): error is KeyActivationConflictError {
  return error instanceof Error && 'code' in error && error.code === 'KEY_ACTIVATION_CONFLICT';
}
export interface Store {
  /** Authoritative clock for protocol timestamps; local adapters use the supplied application/test clock. */
  currentTime(fallbackNow: number): Promise<number>;
  // ---- owners, agents, credentials ----
  putOwner(o: Owner): Promise<void>;
  getOwner(id: string): Promise<Owner | undefined>;
  /** The Owner with this address (compared without regard to case); the most recently created when several share it. */
  getOwnerByEmail(email: string): Promise<Owner | undefined>;
  putOwnerCode(c: OwnerCode): Promise<void>;
  /** ATOMIC. Returns and deletes the Owner's outstanding code. */
  takeOwnerCode(ownerId: string): Promise<OwnerCode | undefined>;
  /** ATOMIC insert-if-absent; an existing handle is never overwritten. */
  putAgent(a: Agent): Promise<boolean>;
  getAgent(handle: string): Promise<Agent | undefined>;
  /** ATOMIC. Requires this immutable Agent identity; disabling increments its fence and invalidates all dependent state. */
  setAgentEnabled(handle: string, enabled: boolean, agentSub: string, now: number): Promise<Agent | undefined>;
  /** ATOMIC. Delete only this identity, with all keys, accounts, consents and delegated credentials; retain signup counts. */
  deleteAgent(handle: string, agentSub: string, now: number): Promise<boolean>;
  listAgentsByOwner(ownerId: string): Promise<Agent[]>;
  putCredential(c: Credential): Promise<void>;
  getCredential(hash: string): Promise<Credential | undefined>;
  listCredentials(filter: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }): Promise<Credential[]>;
  deleteCredential(hash: string): Promise<void>;

  // ---- keys (Section 7) ----
  /** Lookup is scoped to the current Agent at handle. Legacy unscoped lookup returns the active or sole record; ambiguous pending records return undefined. */
  getKey(kid: string, handle?: string): Promise<AgentKey | undefined>;
  listKeys(handle: string): Promise<AgentKey[]>;
  /**
   * ATOMIC. Stores a `pending` key unless the public key was revoked for this handle (`revoked`) or is enrolled
   * now, pending with an unexpired challenge or active and unexpired, for this Agent (`enrolled`). Other Agents'
   * pending or active records do not prevent insertion. A dead record of this Agent's same key is replaced.
   * The Agent sub, Owner and credential must still match the authorization snapshot, otherwise `unauthorized`;
   * check and insert are one transaction.
   */
  insertKey(k: AgentKey, now: number, authorization: ManagementAuthorization): Promise<InsertKeyResult>;
  /**
   * ATOMIC. `pending` becomes `active`, only if this enrollment is still pending and `challenge` is its unconsumed,
   * unexpired challenge and the verified proof window still holds. False otherwise, or AssertionWindowError when
   * the signed proof expired: in particular a revocation while the proof was verified cannot be overwritten.
   * Exclusivity is claimed here: throws KeyActivationConflictError if another Agent has this key active and unexpired.
   */
  activateKey(kid: string, enrollment: string, challenge: string, now: number, assertionWindow?: { notBefore: number; expiresAt: number }): Promise<boolean>;
  /**
   * ATOMIC. A `pending`, `active` or `expired` key becomes `revoked` and is remembered as revoked for its handle. Returns the
   * key when this call revoked it, nothing when there was nothing to revoke. Requires the same enrollment and
   * invalidates its transactions, codes and tokens in the same atomic operation.
   */
  revokeKey(kid: string, enrollment: string, now: number): Promise<AgentKey | undefined>;
  /** ATOMIC. Revoke pending/active keys and, for an Owner request, delegated credentials of the authorized Agent identity. */
  revokeAllKeys(handle: string, authorization: ManagementAuthorization, now: number): Promise<boolean>;
  /** ATOMIC. Changes the label or permissions of this enrollment without touching its status. */
  patchKey(kid: string, enrollment: string, patch: { name?: string; shareOwner?: boolean }): Promise<AgentKey | undefined>;
  /** Deletes the selected record, requiring enrollment when supplied. With pendingExpiredAt, deletes only a
   * still-pending challenge expired by that time; database adapters recheck their authoritative clock. */
  deleteKey(kid: string, enrollment?: string, pendingExpiredAt?: number): Promise<void>;
  wasRevoked(handle: string, kid: string): Promise<boolean>;

  // ---- clients ----
  putClient(c: Client): Promise<void>;
  getClient(clientId: string): Promise<Client | undefined>;

  // ---- transactions (Section 6) ----
  insertTransaction(t: Transaction): Promise<void>;
  getTransaction(id: string): Promise<Transaction | undefined>;
  /** Read-only effective state, including lifecycle expiry and terminal retention. Never persists a transition. */
  readTransaction(id: string, options: { now: number; retainFor: number }): Promise<Transaction | undefined>;
  /**
   * ATOMIC. Compare-and-swap against the open transaction version; return undefined on conflict. Validate subject
   * identity/lifecycle and expiry, admit the signup cap on the FIRST assertion, and commit the transaction,
   * reservation, and consent effects together. Existing consent relied on must still cover the supplied context;
   * otherwise return a review state (or denial for prompt=none). Return the actual state (which may be denied/expired). Completion
   * must use completeTransaction. A losing caller never creates or releases a reservation.
   */
  updateTransaction(t: Transaction, expectedVersion: number, effects: TransitionEffects): Promise<Transaction | undefined>;
  /** Transactions whose stored status is not terminal (an expired one may still be listed; callers look at `expiresAt`). */
  listOpenTransactions(filter: SubjectFilter): Promise<Transaction[]>;

  /** ATOMIC. Validate subject, reservation and expiry; complete, insert code, count Account and release reservation together. */
  completeTransaction(t: Transaction, expectedVersion: number, code: Code, now: number): Promise<Transaction | undefined>;

  // ---- codes and Access Tokens (Section 5) ----
  getCode(hash: string): Promise<Code | undefined>;
  /**
   * ATOMIC. Marks the code used if it is neither used, void nor expired; otherwise says which. One redemption wins.
   * A code that was used already is also marked `replayed`, and its Access Tokens are revoked in the same operation.
   */
  redeemCode(hash: string, now: number): Promise<RedeemResult>;
  /** ATOMIC per code. Voids every matching code that has not been used. */
  voidCodes(filter: SubjectFilter): Promise<void>;
  /** ATOMIC. Issue only for a redeemed, unreplayed code and a current subject lifecycle. */
  insertAccessToken(t: AccessToken, now: number): Promise<boolean>;
  getAccessToken(hash: string): Promise<AccessToken | undefined>;
  /** ATOMIC per token. Revokes every matching Access Token. */
  revokeAccessTokens(filter: SubjectFilter): Promise<void>;

  // ---- consent (Section 6.4) ----
  getConsent(handle: string, clientId: string): Promise<Consent | undefined>;
  listConsents(handle: string): Promise<Consent[]>;
  deleteConsent(handle: string, clientId: string, authorization: ManagementAuthorization): Promise<boolean>;

  // ---- accounts and the per-owner cap (Sections 7.4, 7.6) ----
  getAccount(handle: string, clientId: string): Promise<Account | undefined>;
  listAccounts(handle: string): Promise<Account[]>;
  /** ATOMIC. Authorize against the same Agent identity; disabling increments the Account fence and invalidates dependents. */
  setAccountStatus(handle: string, clientId: string, status: 'enabled' | 'disabled', authorization: ManagementAuthorization, now: number): Promise<Account | undefined>;
  deleteAccount(handle: string, clientId: string): Promise<void>;
  /** Number of Accounts ever created for (Owner, client), including disabled and deleted ones. */
  signupsEver(ownerId: string, clientId: string): Promise<number>;

}

/** Public operations only: internal reservation/count helpers cannot be called outside their atomic transition. */
export const STORE_METHODS: readonly (keyof Store)[] = Object.freeze(Object.keys({
  currentTime: true,
  putOwner: true,
  getOwner: true,
  getOwnerByEmail: true,
  putOwnerCode: true,
  takeOwnerCode: true,
  putAgent: true,
  getAgent: true,
  setAgentEnabled: true,
  deleteAgent: true,
  listAgentsByOwner: true,
  putCredential: true,
  getCredential: true,
  listCredentials: true,
  deleteCredential: true,
  getKey: true,
  listKeys: true,
  insertKey: true,
  activateKey: true,
  revokeKey: true,
  revokeAllKeys: true,
  patchKey: true,
  deleteKey: true,
  wasRevoked: true,
  putClient: true,
  getClient: true,
  insertTransaction: true,
  getTransaction: true,
  readTransaction: true,
  updateTransaction: true,
  listOpenTransactions: true,
  completeTransaction: true,
  getCode: true,
  redeemCode: true,
  voidCodes: true,
  insertAccessToken: true,
  getAccessToken: true,
  revokeAccessTokens: true,
  getConsent: true,
  listConsents: true,
  deleteConsent: true,
  getAccount: true,
  listAccounts: true,
  setAccountStatus: true,
  deleteAccount: true,
  signupsEver: true,
} satisfies Record<keyof Store, true>) as (keyof Store)[]);

/** Reads never rewrite state, including polling an effectively expired transaction. */
export const READ_METHODS: ReadonlySet<keyof Store> = new Set<keyof Store>([
  'currentTime', 'getOwner', 'getOwnerByEmail', 'getAgent', 'listAgentsByOwner', 'getCredential',
  'listCredentials', 'getKey', 'listKeys', 'wasRevoked', 'getClient', 'getTransaction', 'readTransaction',
  'listOpenTransactions', 'getCode', 'getAccessToken', 'getConsent', 'listConsents', 'getAccount',
  'listAccounts', 'signupsEver',
]);


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
export type SyncStore = { [K in keyof Store]: (...args: Parameters<Store[K]>) => Awaited<ReturnType<Store[K]>> };

export class StoreState implements SyncStore {
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

  constructor(snapshot?: string) {
    if (snapshot !== undefined) {
      const parsed = JSON.parse(snapshot);
      if ((parsed.version !== 1 && parsed.version !== 2) || !parsed.maps || !Array.isArray(parsed.revoked)) throw new Error('Unsupported issuer store snapshot');
      for (const name of ['owners', 'agents', 'ownerCodes', 'credentials', 'keys', 'clients', 'transactions', 'codes', 'tokens', 'consents', 'accounts', 'signups'] as const) {
        if (!Array.isArray(parsed.maps[name])) throw new Error(`Invalid store map: ${name}`);
        (this[name] as Map<string, unknown>) = new Map(parsed.maps[name]);
      }
      // Version 1 originally indexed all keys by kid. Derive the scoped index from each value so existing SQLite
      // snapshots and the newer scoped form both load without losing identity, revocation or transaction history.
      this.keys = new Map([...this.keys.values()].map((key) => [this.keyIndex(key.agentSub, key.kid), key]));
      this.revoked = new Set(parsed.revoked);
      this.reservations = new Map(parsed.reservations.map(([key, entries]: [string, [string, { handle: string; expiresAt: number }][]]) => [key, new Map(entries)]));
    }
  }
  exportSnapshot(): string {
    const maps = Object.fromEntries(['owners', 'agents', 'ownerCodes', 'credentials', 'keys', 'clients', 'transactions', 'codes', 'tokens', 'consents', 'accounts', 'signups'].map((name) => [name, [...(this as unknown as Record<string, Map<string, unknown>>)[name]!.entries()]]));
    return JSON.stringify({ version: 2, maps, revoked: [...this.revoked], reservations: [...this.reservations].map(([key, entries]) => [key, [...entries]]) });
  }

  currentTime(fallbackNow: number) { return fallbackNow; }

  putOwner(o: Owner) {
    const previous = this.owners.get(o.id);
    if (previous && previous.ownerSub !== o.ownerSub) throw new Error('Owner subject is immutable');
    if ([...this.owners.values()].some((owner) => owner.id !== o.id && owner.ownerSub === o.ownerSub)) throw new Error('Owner subject already exists');
    this.owners.set(o.id, copy(o));
  }
  getOwner(id: string) { return copy(this.owners.get(id)); }
  getOwnerByEmail(email: string) {
    const wanted = email.toLowerCase();
    return copy([...this.owners.values()].filter((o) => o.email.toLowerCase() === wanted).sort((a, b) => b.createdAt - a.createdAt)[0]);
  }
  putOwnerCode(c: OwnerCode) { this.ownerCodes.set(c.ownerId, copy(c)); }
  takeOwnerCode(ownerId: string) {
    const c = this.ownerCodes.get(ownerId);
    this.ownerCodes.delete(ownerId);
    return c;
  }
  putAgent(a: Agent) {
    if (this.agents.has(a.handle) || [...this.agents.values()].some((agent) => agent.sub === a.sub)) return false;
    this.agents.set(a.handle, copy(a));
    return true;
  }
  getAgent(handle: string) { return copy(this.agents.get(handle)); }
  setAgentEnabled(handle: string, enabled: boolean, agentSub: string, now: number) {
    const a = this.agents.get(handle);
    if (!a || a.sub !== agentSub) return undefined;
    a.enabled = enabled;
    if (!enabled) {
      a.authorizationVersion += 1;
      this.invalidate({ handle }, 'access_denied', now);
    }
    return copy(a);
  }
  deleteAgent(handle: string, agentSub: string, now: number) {
    const a = this.agents.get(handle);
    if (!a || a.sub !== agentSub) return false;
    this.invalidate({ handle }, 'access_denied', now);
    for (const [index, k] of this.keys) if (k.handle === handle && k.agentSub === agentSub) {
      this.revoked.add(`${handle}\u0000${k.kid}`);
      this.keys.delete(index);
    }
    for (const [id, c] of this.consents) if (c.handle === handle) this.consents.delete(id);
    for (const [id, a] of this.accounts) if (a.handle === handle) this.accounts.delete(id);
    for (const [hash, c] of this.credentials) if (c.handle === handle && c.kind === 'delegated') this.credentials.delete(hash);
    this.agents.delete(handle);
    return true;
  }
  private managementCurrent(handle: string, auth: ManagementAuthorization) {
    const agent = this.agents.get(handle);
    const credential = this.credentials.get(auth.hash);
    return agent?.sub === auth.agentSub && agent.ownerId === auth.ownerId && credential?.ownerId === auth.ownerId &&
      credential.kind === auth.kind && (credential.kind === 'owner' || credential.handle === handle);
  }
  private invalidate(filter: SubjectFilter, reason: DenyReason, now: number) {
    for (const t of this.transactions.values()) if (!TERMINAL.has(t.status) && matches({ ...t, txnId: t.id }, filter)) {
      // Expiry may not have been materialized yet. A later lifecycle event must not restart its retention window,
      // including when the asserting key expired before the transaction's own deadline.
      const expired = this.expiredTransaction(t, now);
      t.status = expired?.status ?? 'denied';
      t.reason = expired ? expired.reason : reason;
      t.terminalAt = expired?.terminalAt ?? now;
      t.challenge = undefined;
      t.version += 1;
      if (t.ownerId) this.releaseSignup({ ownerId: t.ownerId, clientId: t.clientId, txnId: t.id });
    }
    this.voidCodes(filter);
    this.revokeAccessTokens(filter);
  }
  private expiredTransaction(t: Transaction, now: number): Transaction | undefined {
    const key = t.kid && t.keyEnrollment ? this.enrollmentKey(t.kid, t.keyEnrollment) : undefined;
    const keyExpiry = key && key.enrollment === t.keyEnrollment && key.agentSub === t.agentSub && key.status !== 'pending'
      ? key.expiresAt : Infinity;
    if (now >= t.expiresAt && t.expiresAt <= keyExpiry) {
      return { ...t, status: 'expired', terminalAt: t.expiresAt, reason: undefined, challenge: undefined };
    }
    if (now >= keyExpiry) return { ...t, status: 'denied', reason: 'key_revoked', terminalAt: keyExpiry, challenge: undefined };
    return undefined;
  }
  private subjectReason(s: { handle?: string; kid?: string; keyEnrollment?: string; agentSub?: string; agentVersion?: number; accountVersion?: number; clientId: string }, now: number): 'key_revoked' | 'access_denied' | undefined {
    const key = s.kid && s.keyEnrollment && this.enrollmentKey(s.kid, s.keyEnrollment);
    if (!key || key.handle !== s.handle || key.enrollment !== s.keyEnrollment || key.agentSub !== s.agentSub || key.status !== 'active' || now >= key.expiresAt) return 'key_revoked';
    const agent = s.handle && this.agents.get(s.handle);
    if (!agent || agent.sub !== s.agentSub || !agent.enabled || agent.authorizationVersion !== s.agentVersion) return 'access_denied';
    const account = this.accounts.get(`${s.handle}\u0000${s.clientId}`);
    if (account?.status === 'disabled' || (account?.authorizationVersion ?? 0) !== s.accountVersion) return 'access_denied';
    return undefined;
  }
  listAgentsByOwner(ownerId: string) { return copy([...this.agents.values()].filter((a) => a.ownerId === ownerId)); }
  putCredential(c: Credential) { this.credentials.set(c.hash, copy(c)); }
  getCredential(hash: string) { return copy(this.credentials.get(hash)); }
  listCredentials(f: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }) {
    return copy([...this.credentials.values()].filter((c) => (f.ownerId === undefined || c.ownerId === f.ownerId) && (f.handle === undefined || c.handle === f.handle) && (f.kind === undefined || c.kind === f.kind)));
  }
  deleteCredential(hash: string) { this.credentials.delete(hash); }

  private keyIndex(agentSub: string, kid: string): string { return `${agentSub}\u0000${kid}`; }
  private enrollmentKey(kid: string, enrollment: string): AgentKey | undefined {
    return [...this.keys.values()].find((key) => key.kid === kid && key.enrollment === enrollment);
  }
  getKey(kid: string, handle?: string) {
    if (handle !== undefined) {
      const agent = this.agents.get(handle);
      return copy(agent ? this.keys.get(this.keyIndex(agent.sub, kid)) : undefined);
    }
    const keys = [...this.keys.values()].filter((key) => key.kid === kid);
    const active = keys.filter((key) => key.status === 'active');
    return copy(active.length === 1 ? active[0] : keys.length === 1 ? keys[0] : undefined);
  }
  listKeys(handle: string) { return copy([...this.keys.values()].filter((k) => k.handle === handle)); }
  insertKey(k: AgentKey, now: number, authorization: ManagementAuthorization): InsertKeyResult {
    if (k.agentSub !== authorization.agentSub || !this.managementCurrent(k.handle, authorization)) return 'unauthorized';
    if (this.revoked.has(`${k.handle}\u0000${k.kid}`)) return 'revoked';
    const index = this.keyIndex(k.agentSub, k.kid);
    const cur = this.keys.get(index);
    const enrolled = cur !== undefined && ((cur.status === 'pending' && cur.challenge !== undefined && now < cur.challenge.expiresAt && now < cur.expiresAt) || (cur.status === 'active' && now < cur.expiresAt));
    if (enrolled) return 'enrolled';
    if (k.status !== 'pending' || k.expiresAt <= now || !k.challenge || k.challenge.expiresAt <= now) return 'unauthorized';
    if ([...this.keys.values()].some((key) => key.enrollment === k.enrollment)) throw new Error('Key enrollment already exists');
    // Preserve the original expiry outcome before this Agent's current-key index points at a new enrollment.
    if (cur?.status === 'active' && now >= cur.expiresAt) this.invalidate({ kid: cur.kid, keyEnrollment: cur.enrollment }, 'key_revoked', cur.expiresAt);
    this.keys.set(index, copy(k));
    return 'ok';
  }
  activateKey(kid: string, enrollment: string, challenge: string, now: number, assertionWindow?: { notBefore: number; expiresAt: number }) {
    const k = this.enrollmentKey(kid, enrollment);
    if (!k || this.agents.get(k.handle)?.sub !== k.agentSub || k.status !== 'pending' || !k.challenge || k.challenge.value !== challenge || now >= k.challenge.expiresAt || now >= k.expiresAt) return false;
    if (assertionWindow && (now < assertionWindow.notBefore || now >= assertionWindow.expiresAt)) throw new AssertionWindowError();
    const active = [...this.keys.values()].filter((key) => key.kid === kid && key.status === 'active');
    if (active.some((key) => now < key.expiresAt)) throw new KeyActivationConflictError();
    for (const expired of active) {
      this.invalidate({ kid, keyEnrollment: expired.enrollment }, 'key_revoked', expired.expiresAt);
      expired.status = 'expired';
    }
    k.status = 'active';
    k.challenge = undefined;
    return true;
  }
  revokeKey(kid: string, enrollment: string, now: number) {
    const k = this.enrollmentKey(kid, enrollment);
    // Individual revocation also forbids reuse after expiry, including an enrollment retired by another Agent.
    if (!k || k.status === 'revoked') return undefined;
    k.status = 'revoked';
    k.revokedAt = now;
    k.challenge = undefined;
    this.revoked.add(`${k.handle}\u0000${k.kid}`);
    this.invalidate({ kid, keyEnrollment: enrollment }, 'key_revoked', now);
    return copy(k);
  }
  revokeAllKeys(handle: string, authorization: ManagementAuthorization, now: number) {
    if (!this.managementCurrent(handle, authorization)) return false;
    for (const k of this.keys.values()) if (k.handle === handle && k.agentSub === authorization.agentSub && (k.status === 'pending' || k.status === 'active')) this.revokeKey(k.kid, k.enrollment, now);
    if (authorization.kind === 'owner') for (const [hash, c] of this.credentials) if (c.handle === handle && c.kind === 'delegated') this.credentials.delete(hash);
    return true;
  }
  patchKey(kid: string, enrollment: string, patch: { name?: string; shareOwner?: boolean }) {
    const k = this.enrollmentKey(kid, enrollment);
    if (!k) return undefined;
    if (patch.name !== undefined) k.name = patch.name;
    if (patch.shareOwner !== undefined) k.permissions.share_owner = patch.shareOwner;
    return copy(k);
  }
  deleteKey(kid: string, enrollment?: string, pendingExpiredAt?: number) {
    const k = enrollment === undefined ? this.getKey(kid) : this.enrollmentKey(kid, enrollment);
    if (!k || (pendingExpiredAt !== undefined && (k.status !== 'pending' || (k.challenge && pendingExpiredAt < k.challenge.expiresAt)))) return;
    this.keys.delete(this.keyIndex(k.agentSub, kid));
  }
  wasRevoked(handle: string, kid: string) { return this.revoked.has(`${handle}\u0000${kid}`); }

  putClient(c: Client) { this.clients.set(c.clientId, copy(c)); }
  getClient(clientId: string) { return copy(this.clients.get(clientId)); }

  insertTransaction(t: Transaction) {
    if (this.transactions.has(t.id)) throw new Error('Transaction already exists');
    this.transactions.set(t.id, copy(t));
  }
  getTransaction(id: string) { return copy(this.transactions.get(id)); }
  readTransaction(id: string, { now, retainFor }: { now: number; retainFor: number }) {
    const stored = this.transactions.get(id);
    if (!stored) return undefined;
    let tx = copy(stored);
    if (!TERMINAL.has(tx.status)) {
      const expired = this.expiredTransaction(tx, now);
      if (expired) tx = expired;
      else if (tx.kid) {
        const reason = this.subjectReason(tx, now);
        if (reason) tx = { ...tx, status: 'denied', reason, terminalAt: now, challenge: undefined };
      }
    }
    return TERMINAL.has(tx.status) && tx.terminalAt !== undefined && now > tx.terminalAt + retainFor ? undefined : tx;
  }
  updateTransaction(t: Transaction, expectedVersion: number, effects: TransitionEffects) {
    const cur = this.transactions.get(t.id);
    if (!cur || cur.version !== expectedVersion || TERMINAL.has(cur.status) || t.status === 'completed') return undefined;
    if (effects.assertionWindow && (effects.now < effects.assertionWindow.notBefore || effects.now >= effects.assertionWindow.expiresAt)) throw new AssertionWindowError();
    const next = copy(t);
    const deny = (reason: DenyReason) => { next.status = 'denied'; next.reason = reason; next.terminalAt = effects.now; next.challenge = undefined; };
    const expired = this.expiredTransaction(cur, effects.now);
    if (expired) { next.status = expired.status; next.reason = expired.reason; next.terminalAt = expired.terminalAt; next.challenge = undefined; }
    else if (next.kid) {
      const reason = this.subjectReason(next, effects.now);
      if (reason) deny(reason);
      else if (cur.status === 'awaiting_agent' && !this.accounts.has(`${next.handle}\u0000${next.clientId}`) && effects.maxSignups !== undefined) {
        // Assertion acceptance owns the reservation: a losing CAS never creates or releases it.
        const reserved = this.reserveSignup({ ownerId: next.ownerId!, clientId: next.clientId, handle: next.handle!, txnId: next.id, expiresAt: next.expiresAt, max: effects.maxSignups, now: effects.now });
        if (!reserved) deny('signup_limit_reached');
        else next.passedCap = true;
      }
      if (cur.status === 'awaiting_agent' && !reason) next.assertedAt = effects.now;
    }
    const consentKey = `${next.handle}\u0000${next.clientId}`;
    const previousConsent = this.consents.get(consentKey);
    if (!TERMINAL.has(next.status) && effects.touchConsent && !effects.consent) {
      const reason = consentRecordReason(previousConsent,
        effects.consentContext ?? { scopes: next.scopes, redirectHost: new URL(next.redirectUri).host }, effects.expireConsentBefore);
      if (reason) {
        next.consentRelied = false;
        next.reviewOutstanding = true;
        next.consentReason = reason;
        if (next.prompt === 'none') deny('consent_required');
        else next.status = next.ownerApprovalOutstanding ? 'awaiting_owner' : 'awaiting_consent';
      }
    }
    if (TERMINAL.has(next.status) && !expired) next.terminalAt = effects.now;
    next.version = expectedVersion + 1;
    this.transactions.set(next.id, next);
    if (TERMINAL.has(next.status) && next.ownerId) this.releaseSignup({ ownerId: next.ownerId, clientId: next.clientId, txnId: next.id });
    else {
      if (next.passedCap && next.ownerId) this.extendSignup({ ownerId: next.ownerId, clientId: next.clientId, txnId: next.id, expiresAt: next.expiresAt });
      if (previousConsent && effects.expireConsentBefore !== undefined && previousConsent.lastUsedAt < effects.expireConsentBefore) this.consents.delete(consentKey);
      if (effects.consent) this.grantConsent(effects.consent, effects.now);
      else if (effects.touchConsent && next.consentRelied && next.status === 'ready' && next.handle) this.touchConsent(next.handle, next.clientId, effects.now);
    }
    return copy(next);
  }
  completeTransaction(t: Transaction, expectedVersion: number, code: Code, now: number) {
    const cur = this.transactions.get(t.id);
    if (!cur || cur.version !== expectedVersion || cur.status !== 'ready') return undefined;
    const dead = this.subjectReason(cur, now);
    const reservation = cur.ownerId && this.reservations.get(`${cur.ownerId}\u0000${cur.clientId}`)?.get(cur.id);
    const needsReservation = cur.passedCap && !this.accounts.has(`${cur.handle}\u0000${cur.clientId}`);
    if (now >= cur.expiresAt || dead || (needsReservation && (!reservation || reservation.expiresAt <= now))) {
      return this.updateTransaction({ ...cur, status: 'denied', reason: dead ?? 'signup_limit_reached', terminalAt: now, challenge: undefined }, expectedVersion, { now });
    }
    if (this.codes.has(code.hash)) throw new Error('Authorization code already exists');
    const next = { ...copy(cur), version: expectedVersion + 1, status: 'completed' as const, terminalAt: now, challenge: undefined, codeIssued: true };
    const issued: Code = { ...copy(code), txnId: cur.id, clientId: cur.clientId, redirectUri: cur.redirectUri,
      codeChallenge: cur.codeChallenge, nonce: cur.nonce, scopes: copy(cur.scopes), handle: cur.handle!, kid: cur.kid!,
      keyEnrollment: cur.keyEnrollment!, agentSub: cur.agentSub!, agentVersion: cur.agentVersion!, accountVersion: cur.accountVersion!,
      authTime: cur.assertedAt!, used: false, voided: false, replayed: undefined };
    this.transactions.set(next.id, next);
    this.codes.set(code.hash, issued);
    this.recordSignIn({ handle: next.handle!, clientId: next.clientId, ownerId: next.ownerId!, txnId: next.id, now });
    return copy(next);
  }
  listOpenTransactions(f: SubjectFilter) {
    return copy([...this.transactions.values()].filter((t) => !TERMINAL.has(t.status) && matches({ ...t, txnId: t.id }, f)));
  }

  getCode(hash: string) { return copy(this.codes.get(hash)); }
  redeemCode(hash: string, now: number): RedeemResult {
    const c = this.codes.get(hash);
    if (!c) return 'unknown';
    if (c.used) {
      c.replayed = true;
      this.revokeAccessTokens({ txnId: c.txnId });
      return 'used';
    }
    if (c.voided || this.subjectReason(c, now)) return 'void';
    if (now >= c.expiresAt) return 'expired';
    c.used = true;
    return 'ok';
  }
  voidCodes(f: SubjectFilter) { for (const c of this.codes.values()) if (!c.used && matches(c, f)) c.voided = true; }
  insertAccessToken(t: AccessToken, now: number) {
    const code = [...this.codes.values()].find((c) => c.txnId === t.txnId);
    if (!code || !code.used || code.replayed || this.subjectReason(code, now) || this.subjectReason(t, now)) return false;
    for (const field of ['handle', 'kid', 'agentSub', 'keyEnrollment', 'agentVersion', 'accountVersion', 'clientId'] as const) {
      if (t[field] !== code[field]) return false;
    }
    if (JSON.stringify(t.scopes) !== JSON.stringify(code.scopes)) return false;
    if (this.tokens.has(t.hash) || [...this.tokens.values()].some((token) => token.txnId === t.txnId)) return false;
    this.tokens.set(t.hash, { ...copy(t), issuedAt: now });
    return true;
  }
  getAccessToken(hash: string) { return copy(this.tokens.get(hash)); }
  revokeAccessTokens(f: SubjectFilter) { for (const t of this.tokens.values()) if (matches(t, f)) t.revoked = true; }

  getConsent(handle: string, clientId: string) { return copy(this.consents.get(`${handle}\u0000${clientId}`)); }
  listConsents(handle: string) { return copy([...this.consents.values()].filter((c) => c.handle === handle)); }
  private grantConsent(c: Omit<Consent, 'createdAt' | 'lastUsedAt'>, now: number) {
    const key = `${c.handle}\u0000${c.clientId}`;
    const cur = this.consents.get(key);
    // Accepting a subset under new terms does not authorize the old scopes under those terms.
    const previous = cur && sameConsentMetadata(cur, c) ? cur : undefined;
    this.consents.set(key, { ...copy(c), scopes: [...new Set([...(previous?.scopes ?? []), ...c.scopes])], createdAt: previous?.createdAt ?? now, lastUsedAt: now });
  }
  private touchConsent(handle: string, clientId: string, now: number) {
    const cur = this.consents.get(`${handle}\u0000${clientId}`);
    if (cur) cur.lastUsedAt = now;
  }
  deleteConsent(handle: string, clientId: string, authorization: ManagementAuthorization) {
    if (!this.managementCurrent(handle, authorization)) return false;
    this.consents.delete(`${handle}\u0000${clientId}`);
    return true;
  }

  getAccount(handle: string, clientId: string) { return copy(this.accounts.get(`${handle}\u0000${clientId}`)); }
  listAccounts(handle: string) { return copy([...this.accounts.values()].filter((a) => a.handle === handle)); }
  setAccountStatus(handle: string, clientId: string, status: 'enabled' | 'disabled', authorization: ManagementAuthorization, now: number) {
    if (!this.managementCurrent(handle, authorization)) return undefined;
    const a = this.accounts.get(`${handle}\u0000${clientId}`);
    if (a) {
      a.status = status;
      if (status === 'disabled') {
        a.authorizationVersion += 1;
        this.invalidate({ handle, clientId }, 'access_denied', now);
      }
    }
    return copy(a);
  }
  deleteAccount(handle: string, clientId: string) { this.accounts.delete(`${handle}\u0000${clientId}`); }
  signupsEver(ownerId: string, clientId: string) { return this.signups.get(`${ownerId}\u0000${clientId}`) ?? 0; }
  private reserveSignup(p: { ownerId: string; clientId: string; handle: string; txnId: string; expiresAt: number; max: number; now: number }) {
    const key = `${p.ownerId}\u0000${p.clientId}`;
    const held = this.reservations.get(key) ?? new Map<string, { handle: string; expiresAt: number }>();
    for (const [txn, r] of held) {
      const t = this.transactions.get(txn);
      // Effective lifecycle expiry releases admission capacity even if nobody polled or persisted a denial.
      if (r.expiresAt <= p.now || !t || TERMINAL.has(t.status) || (t.kid && this.subjectReason(t, p.now))) held.delete(txn);
    }
    const others = new Set<string>();
    for (const r of held.values()) if (r.handle !== p.handle && !this.accounts.has(`${r.handle}\u0000${p.clientId}`)) others.add(r.handle);
    const admitted = (this.signups.get(key) ?? 0) + others.size < p.max;
    if (admitted) held.set(p.txnId, { handle: p.handle, expiresAt: p.expiresAt });
    this.reservations.set(key, held);
    return admitted;
  }
  private extendSignup(p: { ownerId: string; clientId: string; txnId: string; expiresAt: number }) {
    const r = this.reservations.get(`${p.ownerId}\u0000${p.clientId}`)?.get(p.txnId);
    if (r) r.expiresAt = p.expiresAt;
  }
  private releaseSignup(p: { ownerId: string; clientId: string; txnId: string }) {
    this.reservations.get(`${p.ownerId}\u0000${p.clientId}`)?.delete(p.txnId);
  }
  private recordSignIn(p: { handle: string; clientId: string; ownerId: string; txnId: string; now: number }) {
    const key = `${p.ownerId}\u0000${p.clientId}`;
    this.reservations.get(key)?.delete(p.txnId);
    const accountKey = `${p.handle}\u0000${p.clientId}`;
    const existing = this.accounts.get(accountKey);
    if (existing) {
      existing.lastSignedInAt = p.now;
      existing.signInCount += 1;
      return { created: false };
    }
    this.accounts.set(accountKey, { handle: p.handle, clientId: p.clientId, status: 'enabled', authorizationVersion: 0, firstSignedInAt: p.now, lastSignedInAt: p.now, signInCount: 1 });
    this.signups.set(key, (this.signups.get(key) ?? 0) + 1);
    return { created: true };
  }
}

/** Promise facade; every state transition finishes synchronously before it yields to its caller. */
export interface MemoryStore extends Store {}
export class MemoryStore {
  constructor() {
    const state = new StoreState();
    return new Proxy(this, {
      get(target, prop, receiver) {
        const method = Reflect.get(state, prop) as unknown;
        if (typeof prop !== 'string' || !STORE_METHODS.includes(prop as keyof Store) || typeof method !== 'function') return Reflect.get(target, prop, receiver);
        return async (...args: unknown[]) => Reflect.apply(method, state, args);
      },
    });
  }
}
