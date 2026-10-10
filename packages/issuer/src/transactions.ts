// Section 5.3 and Section 6: the Sign-in Transaction.
import { compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { AGENT_KEY_ALGS, ASSERTION_TYP, DISCLOSURE, OWNER_SCOPES, SCOPES, type Scope } from './constants.js';
import type { IssuerContext } from './context.js';
import { OAuthError } from './errors.js';
import { getLiveKey } from './agents.js';
import { TERMINAL, type Client, type Consent, type ConsentReason, type DenyReason, type Transaction, type TxStatus } from './store.js';
import { domainServed, handlesEqual, isPlainObject, nowSeconds, parseHandle, randomId, randomSecret, sha256, typMatches } from './util.js';

export type Viewer =
  | { kind: 'none' }
  | { kind: 'transaction_token' }
  | { kind: 'session' };

export interface CreateParams {
  client: Client;
  redirectUri: string;
  scopes: Scope[];
  state: string;
  nonce: string;
  codeChallenge: string;
  prompt?: 'consent' | 'none';
  loginHint?: string;
  requester?: { user_agent?: string; network?: string };
  /** JSON path: a session_token is minted; HTML path: a session cookie secret. */
  sessionSecret: string;
}

export const txUrl = (ctx: IssuerContext, id: string) => `${ctx.issuer}/transactions/${id}`;

/** Section 5.3: create the transaction. */
export async function createTransaction(ctx: IssuerContext, p: CreateParams): Promise<Transaction> {
  const now = ctx.now();
  const tx: Transaction = {
    id: randomId(),
    clientId: p.client.clientId,
    redirectUri: p.redirectUri,
    scopes: p.scopes,
    state: p.state,
    nonce: p.nonce,
    codeChallenge: p.codeChallenge,
    prompt: p.prompt,
    loginHint: p.loginHint,
    disclosure: p.scopes.map((s) => ({ scope: s, ...DISCLOSURE[s] })),
    requester: p.requester,
    status: 'awaiting_agent',
    challenge: randomSecret(),
    createdAt: now,
    expiresAt: now + ctx.constants.T_TXN,
    acceptDisclosure: false,
    deliverToSession: false,
    ownerApprovalOutstanding: false,
    reviewOutstanding: false,
    passedCap: false,
    sessionSecretHash: sha256(p.sessionSecret),
    codeIssued: false,
  };
  await ctx.store.putTransaction(tx);
  return tx;
}

/** Applies expiry lazily (Section 6.2). */
export function refresh(ctx: IssuerContext, tx: Transaction): Transaction {
  if (!TERMINAL.has(tx.status) && ctx.now() >= tx.expiresAt) setTerminal(ctx, tx, 'expired');
  return tx;
}

export function setTerminal(ctx: IssuerContext, tx: Transaction, status: 'completed' | 'denied' | 'expired', reason?: DenyReason): void {
  tx.status = status;
  if (reason) tx.reason = reason;
  tx.terminalAt = ctx.now();
  tx.challenge = undefined;
  if (status !== 'completed') tx.continueSecret ??= randomSecret();
}

/** Loads a transaction or throws 404 `invalid_transaction` (Section 6.7); retains terminal ones for T_RETAIN. */
export async function loadTransaction(ctx: IssuerContext, id: string): Promise<Transaction> {
  const tx = await ctx.store.getTransaction(id);
  if (!tx) throw new OAuthError(404, 'invalid_transaction');
  refresh(ctx, tx);
  if (TERMINAL.has(tx.status) && tx.terminalAt !== undefined && ctx.now() > tx.terminalAt + ctx.constants.T_RETAIN) {
    throw new OAuthError(404, 'invalid_transaction');
  }
  return tx;
}

/** Section 6.1: the Transaction Resource as seen by `viewer`. */
export function resource(ctx: IssuerContext, tx: Transaction, client: Client, viewer: Viewer): Record<string, unknown> {
  const base = txUrl(ctx, tx.id);
  const r: Record<string, unknown> = {
    transaction_id: tx.id,
    iss: ctx.issuer,
    url: base,
    status: tx.status,
    next: next(ctx, tx, viewer),
    expires_at: tx.expiresAt,
    client: {
      client_id: client.clientId,
      client_type: client.type,
      redirect_host: new URL(tx.redirectUri).host,
      client_name: client.clientName,
      logo_uri: client.logoUri,
      tos_uri: client.tosUri,
      policy_uri: client.policyUri,
    },
    requested_scopes: tx.scopes,
    disclosure: tx.disclosure,
  };
  if (tx.requester) r.requester = tx.requester;
  if (tx.status === 'awaiting_agent') r.challenge = tx.challenge;
  if (tx.status === 'awaiting_consent') r.consent_reason = tx.consentReason;
  if (tx.loginHint) r.login_hint = tx.loginHint;
  if (tx.status === 'denied') r.reason = tx.reason;
  return r;
}

function next(ctx: IssuerContext, tx: Transaction, viewer: Viewer): Record<string, unknown> {
  const base = txUrl(ctx, tx.id);
  switch (tx.status) {
    case 'awaiting_agent':
      return { action: 'assert', method: 'POST', url: `${base}/assertion` };
    case 'awaiting_owner':
      return { action: 'await_owner', method: 'GET', url: base, retry_after: 5 };
    case 'awaiting_consent':
      return { action: 'review', method: 'POST', url: `${base}/review` };
    case 'completed':
      return { action: 'none' };
    case 'ready':
    case 'denied':
    case 'expired': {
      // Section 6.5: the continue URL goes to the transaction_token holder, and to the Session Holder only
      // when the accepted assertion carried deliver_to_session.
      const release = viewer.kind === 'transaction_token' || (viewer.kind === 'session' && tx.deliverToSession);
      const n: Record<string, unknown> = { action: 'continue', method: 'GET' };
      if (release && tx.continueSecret) n.url = `${base}/continue/${tx.continueSecret}`;
      return n;
    }
  }
}

/** Identifies the requester of a transaction resource from its credentials (Section 6.5). */
export function identifyViewer(tx: Transaction, bearer: string | null, cookieSecret: string | null): Viewer {
  if (bearer) {
    const h = sha256(bearer);
    if (tx.transactionTokenHash && h === tx.transactionTokenHash) return { kind: 'transaction_token' };
    if (tx.sessionSecretHash && h === tx.sessionSecretHash) return { kind: 'session' };
    throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  }
  if (cookieSecret && tx.sessionSecretHash && sha256(cookieSecret) === tx.sessionSecretHash) return { kind: 'session' };
  return { kind: 'none' };
}

/** Section 6.4: whether a review is required, and why. */
export function reviewReason(ctx: IssuerContext, tx: Transaction, client: Client, consent: Consent | undefined): ConsentReason | null {
  if (!consent) return 'first_visit';
  const redirectHost = new URL(tx.redirectUri).host;
  const changed =
    !tx.scopes.every((s) => consent.scopes.includes(s)) ||
    consent.redirectHost !== redirectHost ||
    consent.clientName !== client.clientName ||
    consent.tosUri !== client.tosUri ||
    consent.policyUri !== client.policyUri;
  if (changed) return 'material_change';
  if (ctx.now() - consent.lastUsedAt > ctx.constants.T_CONSENT) return 'expired';
  if (tx.prompt === 'consent') return 'prompt_consent';
  if (client.requireReview) return 'policy';
  return null;
}

async function writeConsent(ctx: IssuerContext, tx: Transaction, client: Client): Promise<void> {
  const existing = await ctx.store.getConsent(tx.handle!, tx.clientId);
  const now = ctx.now();
  await ctx.store.putConsent({
    handle: tx.handle!,
    clientId: tx.clientId,
    scopes: [...new Set([...(existing?.scopes ?? []), ...tx.scopes])],
    redirectHost: new URL(tx.redirectUri).host,
    clientName: client.clientName,
    tosUri: client.tosUri,
    policyUri: client.policyUri,
    createdAt: existing?.createdAt ?? now,
    lastUsedAt: now,
  });
}

function setReady(ctx: IssuerContext, tx: Transaction): void {
  tx.status = 'ready';
  tx.continueSecret ??= randomSecret();
}

/**
 * Section 6.7 precedence: `invalid_transaction` (loading), then `invalid_token`, then `transaction_expired`, then any
 * other error. The two guards below are applied in that order before a request body or the status is looked at.
 */
export function requireTransactionToken(viewer: Viewer): void {
  if (viewer.kind !== 'transaction_token') throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
}
export function requireOpen(tx: Transaction): void {
  if (TERMINAL.has(tx.status)) throw new OAuthError(410, 'transaction_expired');
}

/** Section 6.3: verify an assertion and advance the transaction. Returns the transaction_token. */
export async function assert(ctx: IssuerContext, tx: Transaction, client: Client, body: unknown): Promise<string> {
  requireOpen(tx);
  if (!isPlainObject(body) || typeof body.assertion !== 'string') throw new OAuthError(400, 'invalid_request', 'assertion required');
  const jws = body.assertion;
  const c = ctx.constants;
  const bad = (d: string) => new OAuthError(400, 'invalid_assertion', d);

  // Step 1: size, header, parse.
  if (Buffer.byteLength(jws) > c.N_ASSERTION) throw bad('assertion too large');
  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    throw bad('malformed JWS');
  }
  if (!AGENT_KEY_ALGS.includes(header.alg as never)) throw bad('alg not permitted');
  if (!typMatches(header.typ, ASSERTION_TYP)) throw bad('typ');
  if (typeof header.kid !== 'string') throw bad('kid required');
  for (const f of ['jwk', 'jku', 'x5u', 'x5c', 'crit'] as const) if (header[f] !== undefined) throw bad(`header ${f} not permitted`);
  let payload: Record<string, unknown>;
  try {
    const parts = jws.split('.');
    payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    if (!isPlainObject(payload)) throw new Error();
  } catch {
    throw bad('malformed payload');
  }
  if (typeof payload.iss !== 'string' || payload.sub !== payload.iss) throw bad('iss and sub must both be the handle');
  const parsed = parseHandle(payload.iss);
  if (!parsed) throw bad('handle syntax');

  // Step 2: resolve the key.
  const key = await getLiveKey(ctx, header.kid);
  if (!key || !handlesEqual(key.handle, parsed.handle) || !domainServed(parsed.domain, ctx.handleDomains)) throw new OAuthError(401, 'unknown_key');
  if (key.status === 'active' && ctx.now() >= key.expiresAt) key.status = 'expired';
  if (key.status !== 'active') throw new OAuthError(401, 'key_revoked');
  if (header.alg !== 'ES256') throw bad('alg does not match the key'); // only P-256 keys are enrolled

  // Step 3: signature.
  try {
    await compactVerify(jws, await importJWK(key.jwk, 'ES256'), { algorithms: ['ES256'] });
  } catch {
    throw new OAuthError(401, 'invalid_signature');
  }

  // Step 4: claims.
  const now = ctx.now();
  if (payload.aud !== ctx.issuer) throw bad('aud');
  if (payload.txn !== tx.id) throw bad('txn');
  if (tx.status !== 'awaiting_agent' || payload.nonce !== tx.challenge) {
    if (tx.status !== 'awaiting_agent') throw new OAuthError(409, 'assertion_replayed');
    throw bad('nonce');
  }
  const iat = payload.iat;
  const exp = payload.exp;
  if (typeof iat !== 'number' || typeof exp !== 'number') throw bad('iat and exp required');
  if (exp > iat + c.T_ASSERT) throw bad('exp too far from iat');
  if (now >= exp) throw bad('expired');
  if (iat < now - c.T_ASSERT || iat > now + c.T_SKEW) throw bad('iat outside window');
  if (typeof payload.jti !== 'string') throw bad('jti required');
  if (payload.accept_disclosure !== undefined && typeof payload.accept_disclosure !== 'boolean') throw bad('accept_disclosure');
  if (payload.deliver_to_session !== undefined && typeof payload.deliver_to_session !== 'boolean') throw bad('deliver_to_session');

  // Step 5: login_hint.
  if (tx.loginHint && !handlesEqual(tx.loginHint, parsed.handle)) throw bad('login_hint mismatch');
  // Step 6: replay (covered above by the status check).
  const agent = await ctx.store.getAgent(key.handle);
  if (!agent || !agent.enabled) throw new OAuthError(401, 'unknown_key');

  // Step 7: consume the challenge and record the authentication event.
  tx.challenge = undefined;
  tx.handle = agent.handle;
  tx.kid = key.kid;
  tx.ownerId = agent.ownerId;
  tx.assertedAt = now;
  tx.acceptDisclosure = payload.accept_disclosure === true;
  tx.deliverToSession = payload.deliver_to_session === true;
  const token = randomSecret();
  tx.transactionTokenHash = sha256(token);

  // Step 8: disabled Account.
  const account = await ctx.store.getAccount(agent.handle, tx.clientId);
  if (account?.status === 'disabled') {
    setTerminal(ctx, tx, 'denied', 'access_denied');
    await ctx.store.putTransaction(tx);
    return token;
  }
  // Step 9: per-owner cap (Section 7.6).
  if (!account && client.maxSignupsPerOwner !== undefined) {
    const ever = await ctx.store.signupsEver(agent.ownerId, tx.clientId);
    const inflight = (await ctx.store.listOpenTransactions({ ownerId: agent.ownerId, clientId: tx.clientId })).filter((t) => t.passedCap && t.id !== tx.id).length;
    if (ever + inflight >= client.maxSignupsPerOwner) {
      setTerminal(ctx, tx, 'denied', 'signup_limit_reached');
      await ctx.store.putTransaction(tx);
      return token;
    }
    tx.passedCap = true;
  }
  // Step 10: gates.
  const wantsOwner = tx.scopes.some((s) => OWNER_SCOPES.includes(s));
  tx.ownerApprovalOutstanding = wantsOwner && !key.permissions.share_owner;
  const consent = await ctx.store.getConsent(agent.handle, tx.clientId);
  const reason = reviewReason(ctx, tx, client, consent);
  if (reason === 'expired') await ctx.store.deleteConsent(agent.handle, tx.clientId); // Section 6.4: unused for T_CONSENT
  const satisfiable = reason === 'first_visit' || reason === 'material_change' || reason === 'expired';
  tx.reviewOutstanding = reason !== null && !(tx.acceptDisclosure && satisfiable);
  tx.consentReason = reason ?? undefined;
  if (tx.prompt === 'none' && tx.reviewOutstanding) {
    setTerminal(ctx, tx, 'denied', 'consent_required');
  } else if (tx.prompt === 'none' && tx.ownerApprovalOutstanding) {
    setTerminal(ctx, tx, 'denied', 'interaction_required');
  } else {
    if (tx.acceptDisclosure && !tx.reviewOutstanding) await writeConsent(ctx, tx, client);
    if (tx.ownerApprovalOutstanding) {
      tx.status = 'awaiting_owner';
      tx.expiresAt = Math.max(tx.expiresAt, tx.createdAt + ctx.constants.T_OWNER); // Section 6.6
    } else if (tx.reviewOutstanding) tx.status = 'awaiting_consent';
    else setReady(ctx, tx);
  }
  await ctx.store.putTransaction(tx);
  return token;
}

/** Section 6.4: the review decision, authorised by the transaction_token only. */
export async function review(ctx: IssuerContext, tx: Transaction, client: Client, viewer: Viewer, body: unknown): Promise<void> {
  requireTransactionToken(viewer); // the session binding does not authorise this step
  requireOpen(tx);
  if (tx.status !== 'awaiting_consent') throw new OAuthError(400, 'invalid_request', 'no review is outstanding');
  if (!isPlainObject(body) || (body.decision !== 'allow' && body.decision !== 'deny')) throw new OAuthError(400, 'invalid_request', 'decision must be allow or deny');
  if (body.decision === 'deny') {
    setTerminal(ctx, tx, 'denied', 'cancelled');
  } else {
    await writeConsent(ctx, tx, client);
    tx.reviewOutstanding = false;
    if (tx.ownerApprovalOutstanding) tx.status = 'awaiting_owner';
    else setReady(ctx, tx);
  }
  await ctx.store.putTransaction(tx);
}

/** Section 6.6: the Owner's decision, given with an Owner Credential of the asserting Agent's Owner. */
export async function ownerDecision(ctx: IssuerContext, tx: Transaction, ownerId: string, decision: unknown): Promise<void> {
  if (TERMINAL.has(tx.status)) throw new OAuthError(410, 'transaction_expired');
  if (tx.status !== 'awaiting_owner') throw new OAuthError(400, 'invalid_request', 'no approval is outstanding');
  if (tx.ownerId !== ownerId) throw new OAuthError(404, 'invalid_transaction');
  if (decision !== 'approve' && decision !== 'refuse') throw new OAuthError(400, 'invalid_request', 'decision must be approve or refuse');
  if (decision === 'refuse') setTerminal(ctx, tx, 'denied', 'owner_declined');
  else {
    tx.ownerApprovalOutstanding = false;
    if (tx.reviewOutstanding) tx.status = 'awaiting_consent';
    else setReady(ctx, tx);
  }
  await ctx.store.putTransaction(tx);
}

export interface ContinueResult { redirect: string }

/** Section 6.5: follow the continue URL. Issues the code once for `ready`. */
export async function cont(ctx: IssuerContext, tx: Transaction, secret: string, viewer: Viewer): Promise<ContinueResult> {
  const release = viewer.kind === 'transaction_token' || (viewer.kind === 'session' && tx.deliverToSession);
  if (!release) throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  if (!tx.continueSecret || secret !== tx.continueSecret) throw new OAuthError(404, 'invalid_transaction');
  const u = new URL(tx.redirectUri);
  u.searchParams.set('state', tx.state);
  u.searchParams.set('iss', ctx.issuer);
  if (tx.status === 'ready') {
    const code = randomSecret();
    await ctx.store.putCode({
      hash: sha256(code),
      txnId: tx.id,
      clientId: tx.clientId,
      redirectUri: tx.redirectUri,
      codeChallenge: tx.codeChallenge,
      nonce: tx.nonce,
      scopes: tx.scopes,
      handle: tx.handle!,
      kid: tx.kid!,
      authTime: tx.assertedAt!,
      expiresAt: ctx.now() + ctx.constants.T_CODE,
      used: false,
      voided: false,
    });
    tx.codeIssued = true;
    setTerminal(ctx, tx, 'completed');
    // Section 7.4: the Account is created or updated at the first completed transaction.
    const existing = await ctx.store.getAccount(tx.handle!, tx.clientId);
    const now = ctx.now();
    if (existing) {
      existing.lastSignedInAt = now;
      existing.signInCount += 1;
      await ctx.store.putAccount(existing);
    } else {
      await ctx.store.putAccount({ handle: tx.handle!, clientId: tx.clientId, status: 'enabled', firstSignedInAt: now, lastSignedInAt: now, signInCount: 1 });
      await ctx.store.countSignup(tx.ownerId!, tx.clientId);
    }
    await ctx.store.putTransaction(tx);
    u.searchParams.set('code', code);
    return { redirect: u.href };
  }
  if (tx.status === 'completed') throw new OAuthError(410, 'transaction_expired');
  if (tx.status === 'denied' || tx.status === 'expired') {
    const { error, description } = redirectError(tx);
    u.searchParams.set('error', error);
    if (description) u.searchParams.set('error_description', description);
    return { redirect: u.href };
  }
  throw new OAuthError(400, 'invalid_request', 'transaction is not ready');
}

/** Section 5.5 table. */
export function redirectError(tx: Transaction): { error: string; description?: string } {
  if (tx.status === 'expired') return { error: 'access_denied', description: 'transaction_expired' };
  switch (tx.reason) {
    case 'owner_declined':
      return { error: 'access_denied', description: 'owner_declined' };
    case 'consent_required':
      return { error: 'consent_required' };
    case 'interaction_required':
      return { error: 'interaction_required' };
    case 'signup_limit_reached':
      return { error: 'signup_limit_reached' };
    default:
      return { error: 'access_denied' };
  }
}

export const isTerminal = (s: TxStatus) => TERMINAL.has(s);
export const scopeList = (raw: string): Scope[] =>
  [...new Set(raw.split(' ').filter((s) => (SCOPES as readonly string[]).includes(s)))] as Scope[];
