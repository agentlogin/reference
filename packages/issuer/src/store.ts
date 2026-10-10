// Storage model and an in-memory implementation. Every method is async so that a database-backed
// store can replace it without touching the protocol code.
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
/** Owner Credential or Delegated Credential (Section 1.2), stored hashed. */
export interface Credential {
  hash: string;
  ownerId: string;
  kind: 'owner' | 'delegated';
  handle?: string; // delegated credentials are bound to one handle
  createdAt: number;
}
export type KeyStatus = 'pending' | 'active' | 'revoked' | 'expired';
export interface P256Jwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }
export interface AgentKey {
  kid: string;
  handle: string;
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
  ownerId?: string;
  assertedAt?: number;
  acceptDisclosure: boolean;
  deliverToSession: boolean;
  ownerApprovalOutstanding: boolean;
  reviewOutstanding: boolean;
  passedCap: boolean; // passed step 9 without an existing Account (counts toward the cap, Section 7.6)
  // credentials (hashed) and the continue URL secret
  transactionTokenHash?: string;
  sessionSecretHash?: string;
  continueSecret?: string;
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
  authTime: number;
  expiresAt: number;
  used: boolean;
  voided: boolean;
}
export interface AccessToken {
  hash: string;
  txnId: string;
  clientId: string;
  handle: string;
  kid: string;
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

export interface Store {
  // owners, agents, credentials
  putOwner(o: Owner): Promise<void>;
  getOwner(id: string): Promise<Owner | undefined>;
  putAgent(a: Agent): Promise<void>;
  getAgent(handle: string): Promise<Agent | undefined>;
  listAgentsByOwner(ownerId: string): Promise<Agent[]>;
  putCredential(c: Credential): Promise<void>;
  getCredential(hash: string): Promise<Credential | undefined>;
  listCredentials(filter: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }): Promise<Credential[]>;
  deleteCredential(hash: string): Promise<void>;
  // keys
  putKey(k: AgentKey): Promise<void>;
  getKey(kid: string): Promise<AgentKey | undefined>;
  listKeys(handle: string): Promise<AgentKey[]>;
  wasRevoked(handle: string, kid: string): Promise<boolean>;
  rememberRevoked(handle: string, kid: string): Promise<void>;
  // clients
  putClient(c: Client): Promise<void>;
  getClient(clientId: string): Promise<Client | undefined>;
  // transactions, codes, tokens
  putTransaction(t: Transaction): Promise<void>;
  getTransaction(id: string): Promise<Transaction | undefined>;
  getTransactionByTokenHash(hash: string): Promise<Transaction | undefined>;
  listOpenTransactions(filter: { kid?: string; handle?: string; clientId?: string; ownerId?: string }): Promise<Transaction[]>;
  putCode(c: Code): Promise<void>;
  getCode(hash: string): Promise<Code | undefined>;
  listCodes(filter: { txnId?: string; kid?: string; handle?: string; clientId?: string }): Promise<Code[]>;
  putAccessToken(t: AccessToken): Promise<void>;
  getAccessToken(hash: string): Promise<AccessToken | undefined>;
  listAccessTokens(filter: { kid?: string; handle?: string; clientId?: string }): Promise<AccessToken[]>;
  // consent, accounts, caps
  putConsent(c: Consent): Promise<void>;
  getConsent(handle: string, clientId: string): Promise<Consent | undefined>;
  deleteConsent(handle: string, clientId: string): Promise<void>;
  putAccount(a: Account): Promise<void>;
  getAccount(handle: string, clientId: string): Promise<Account | undefined>;
  listAccounts(handle: string): Promise<Account[]>;
  /** Number of Accounts ever created for (Owner, client), including disabled and deleted ones. */
  signupsEver(ownerId: string, clientId: string): Promise<number>;
  countSignup(ownerId: string, clientId: string): Promise<void>;
}

export class MemoryStore implements Store {
  private owners = new Map<string, Owner>();
  private agents = new Map<string, Agent>();
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

  async putOwner(o: Owner) { this.owners.set(o.id, o); }
  async getOwner(id: string) { return this.owners.get(id); }
  async putAgent(a: Agent) { this.agents.set(a.handle, a); }
  async getAgent(handle: string) { return this.agents.get(handle); }
  async listAgentsByOwner(ownerId: string) { return [...this.agents.values()].filter((a) => a.ownerId === ownerId); }
  async putCredential(c: Credential) { this.credentials.set(c.hash, c); }
  async getCredential(hash: string) { return this.credentials.get(hash); }
  async listCredentials(f: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }) {
    return [...this.credentials.values()].filter((c) => (f.ownerId === undefined || c.ownerId === f.ownerId) && (f.handle === undefined || c.handle === f.handle) && (f.kind === undefined || c.kind === f.kind));
  }
  async deleteCredential(hash: string) { this.credentials.delete(hash); }
  async putKey(k: AgentKey) { this.keys.set(k.kid, k); }
  async getKey(kid: string) { return this.keys.get(kid); }
  async listKeys(handle: string) { return [...this.keys.values()].filter((k) => k.handle === handle); }
  async wasRevoked(handle: string, kid: string) { return this.revoked.has(`${handle}\u0000${kid}`); }
  async rememberRevoked(handle: string, kid: string) { this.revoked.add(`${handle}\u0000${kid}`); }
  async putClient(c: Client) { this.clients.set(c.clientId, c); }
  async getClient(clientId: string) { return this.clients.get(clientId); }
  async putTransaction(t: Transaction) { this.transactions.set(t.id, t); }
  async getTransaction(id: string) { return this.transactions.get(id); }
  async getTransactionByTokenHash(hash: string) {
    return [...this.transactions.values()].find((t) => t.transactionTokenHash === hash);
  }
  async listOpenTransactions(f: { kid?: string; handle?: string; clientId?: string; ownerId?: string }) {
    return [...this.transactions.values()].filter(
      (t) =>
        !TERMINAL.has(t.status) &&
        (f.kid === undefined || t.kid === f.kid) &&
        (f.handle === undefined || t.handle === f.handle) &&
        (f.clientId === undefined || t.clientId === f.clientId) &&
        (f.ownerId === undefined || t.ownerId === f.ownerId),
    );
  }
  async putCode(c: Code) { this.codes.set(c.hash, c); }
  async getCode(hash: string) { return this.codes.get(hash); }
  async listCodes(f: { txnId?: string; kid?: string; handle?: string; clientId?: string }) {
    return [...this.codes.values()].filter(
      (c) =>
        (f.txnId === undefined || c.txnId === f.txnId) &&
        (f.kid === undefined || c.kid === f.kid) &&
        (f.handle === undefined || c.handle === f.handle) &&
        (f.clientId === undefined || c.clientId === f.clientId),
    );
  }
  async putAccessToken(t: AccessToken) { this.tokens.set(t.hash, t); }
  async getAccessToken(hash: string) { return this.tokens.get(hash); }
  async listAccessTokens(f: { kid?: string; handle?: string; clientId?: string }) {
    return [...this.tokens.values()].filter(
      (t) =>
        (f.kid === undefined || t.kid === f.kid) &&
        (f.handle === undefined || t.handle === f.handle) &&
        (f.clientId === undefined || t.clientId === f.clientId),
    );
  }
  async putConsent(c: Consent) { this.consents.set(`${c.handle}\u0000${c.clientId}`, c); }
  async getConsent(handle: string, clientId: string) { return this.consents.get(`${handle}\u0000${clientId}`); }
  async deleteConsent(handle: string, clientId: string) { this.consents.delete(`${handle}\u0000${clientId}`); }
  async putAccount(a: Account) { this.accounts.set(`${a.handle}\u0000${a.clientId}`, a); }
  async getAccount(handle: string, clientId: string) { return this.accounts.get(`${handle}\u0000${clientId}`); }
  async listAccounts(handle: string) { return [...this.accounts.values()].filter((a) => a.handle === handle); }
  async signupsEver(ownerId: string, clientId: string) { return this.signups.get(`${ownerId}\u0000${clientId}`) ?? 0; }
  async countSignup(ownerId: string, clientId: string) {
    const k = `${ownerId}\u0000${clientId}`;
    this.signups.set(k, (this.signups.get(k) ?? 0) + 1);
  }
}
