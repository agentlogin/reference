// Section 5.3 and Section 6: the Sign-in Transaction.
import { compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { AGENT_KEY_ALGS, ASSERTION_TYP, DISCLOSURE, OWNER_SCOPES, SCOPES, type Scope } from './constants.js';
import type { IssuerContext } from './context.js';
import { OAuthError } from './errors.js';
import { getLiveKey } from './agents.js';
import { ownerClaimsAvailable } from './tokens.js';
import { commit, denyTransaction, effective, ended, releasePlace, subjectState } from './state.js';
import { TERMINAL, type Client, type Consent, type ConsentReason, type DenyReason, type Transaction, type TxStatus } from './store.js';
import { domainServed, handlesEqual, isPlainObject, parseHandle, randomId, randomSecret, sha256, typMatches } from './util.js';

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
    version: 0,
    continueSecret: randomSecret(),
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
  await ctx.store.insertTransaction(tx);
  return tx;
}

/**
 * Loads a transaction as it stands now, or throws 404 `invalid_transaction` (Section 6.7); terminal ones are retained
 * for T_RETAIN. An open transaction whose asserting key has been revoked or has expired, or whose Agent or Account
 * has been disabled, is ended here if nothing ended it before (Section 7.4 table): no later step can then proceed.
 */
export async function loadTransaction(ctx: IssuerContext, id: string): Promise<Transaction> {
  const stored = await ctx.store.getTransaction(id);
  if (!stored) throw new OAuthError(404, 'invalid_transaction');
  let tx = effective(ctx, stored);
  if (!TERMINAL.has(tx.status) && tx.kid && tx.handle && tx.keyEnrollment) {
    const dead = await subjectState(ctx, { handle: tx.handle, kid: tx.kid, keyEnrollment: tx.keyEnrollment, clientId: tx.clientId });
    if (dead) tx = (await denyTransaction(ctx, tx.id, dead)) ?? tx;
  }
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
      if (release) n.url = `${base}/continue/${tx.continueSecret}`;
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
/**
 * Section 6.4: why a review is required. `record` is a reason that the Agent's acceptance of the disclosure
 * satisfies (the Consent Record is missing, outdated or expired); `forced` is one that it does not (the request or
 * the client demands a review).
 */
export function reviewReasons(ctx: IssuerContext, tx: Transaction, client: Client, consent: Consent | undefined): { record: ConsentReason | null; forced: ConsentReason | null } {
  let record: ConsentReason | null = null;
  if (!consent) record = 'first_visit';
  else {
    const changed =
      !tx.scopes.every((s) => consent.scopes.includes(s)) ||
      consent.redirectHost !== new URL(tx.redirectUri).host ||
      consent.clientName !== client.clientName ||
      consent.tosUri !== client.tosUri ||
      consent.policyUri !== client.policyUri;
    if (changed) record = 'material_change';
    else if (ctx.now() - consent.lastUsedAt > ctx.constants.T_CONSENT) record = 'expired';
  }
  const forced: ConsentReason | null = tx.prompt === 'consent' ? 'prompt_consent' : client.requireReview ? 'policy' : null;
  return { record, forced };
}

/** What follows an accepted change: the effects that are not themselves the state transition. */
async function afterCommit(ctx: IssuerContext, tx: Transaction, client: Client, o: { grantConsent?: boolean } = {}): Promise<void> {
  if (o.grantConsent && tx.handle) {
    await ctx.store.grantConsent({ handle: tx.handle, clientId: tx.clientId, scopes: tx.scopes, redirectHost: new URL(tx.redirectUri).host, clientName: client.clientName, tosUri: client.tosUri, policyUri: client.policyUri }, ctx.now());
  } else if (tx.status === 'ready' && tx.consentRelied && tx.handle) {
    // A Consent Record that let the sign-in through without a new acceptance is used at this moment, and only now is
    // its last use renewed: a sign-in that ends denied leaves the record's clock alone (Section 6.4).
    await ctx.store.touchConsent(tx.handle, tx.clientId, ctx.now());
  }
  if (TERMINAL.has(tx.status)) await releasePlace(ctx, tx);
  else if (tx.passedCap && tx.ownerId) await ctx.store.extendSignup({ ownerId: tx.ownerId, clientId: tx.clientId, txnId: tx.id, expiresAt: tx.expiresAt });
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

/**
 * Section 6.3: verify an assertion and advance the transaction. Returns the transaction as accepted and its
 * transaction_token. Steps 6 and 7 are one conditional write: of several assertions for one transaction, at whatever
 * issuer process they arrive, one is accepted and the others are answered `assertion_replayed`.
 */
export async function assert(ctx: IssuerContext, loaded: Transaction, client: Client, body: unknown): Promise<{ tx: Transaction; token: string }> {
  const tx = loaded;
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
  if (key.status !== 'active' || ctx.now() >= key.expiresAt) throw new OAuthError(401, 'key_revoked');
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
  const agent = await ctx.store.getAgent(key.handle);
  if (!agent || !agent.enabled) throw new OAuthError(401, 'unknown_key');
  const token = randomSecret();
  const subject = { handle: agent.handle, kid: key.kid, keyEnrollment: key.enrollment, clientId: tx.clientId };

  for (let current = tx; ; ) {
    // Step 6: one assertion per transaction. Decided again on every attempt, against the transaction as it is now.
    if (TERMINAL.has(current.status)) throw new OAuthError(410, 'transaction_expired');
    if (current.status !== 'awaiting_agent') throw new OAuthError(409, 'assertion_replayed');
    if (payload.nonce !== current.challenge) throw bad('nonce');

    // Step 7: the challenge is consumed and the authentication event recorded.
    let next: Transaction = {
      ...current,
      challenge: undefined,
      handle: agent.handle,
      kid: key.kid,
      keyEnrollment: key.enrollment,
      ownerId: agent.ownerId,
      assertedAt: now,
      acceptDisclosure: payload.accept_disclosure === true,
      deliverToSession: payload.deliver_to_session === true,
      transactionTokenHash: sha256(token),
    };
    let grantConsent = false;
    let reserved = false;
    // Step 8: disabled Account.
    const account = await ctx.store.getAccount(agent.handle, next.clientId);
    if (account?.status === 'disabled') next = ended(ctx, next, 'denied', 'access_denied');
    else {
      // Step 9: per-owner cap (Section 7.6). The check and the reservation are one atomic store operation.
      if (!account && client.maxSignupsPerOwner !== undefined) {
        reserved = await ctx.store.reserveSignup({ ownerId: agent.ownerId, clientId: next.clientId, handle: agent.handle, txnId: next.id, expiresAt: next.expiresAt, max: client.maxSignupsPerOwner, now: ctx.now() });
        if (!reserved) next = ended(ctx, next, 'denied', 'signup_limit_reached');
        else next.passedCap = true;
      }
      if (next.status !== 'denied') ({ next, grantConsent } = await gates(ctx, next, client, key.permissions.share_owner, agent.ownerId));
    }

    if (await commit(ctx, next, current.version)) {
      await afterCommit(ctx, next, client, { grantConsent });
      // The key, the Agent and the Account are read again now that the transaction names them: a revocation or a
      // disable that happened meanwhile either saw this transaction and ended it, or is seen here.
      const dead = TERMINAL.has(next.status) ? null : await subjectState(ctx, subject);
      if (dead) next = (await denyTransaction(ctx, next.id, dead)) ?? next;
      return { tx: next, token };
    }
    // Another request changed the transaction first: give back the place and decide again.
    if (reserved) await ctx.store.releaseSignup({ ownerId: agent.ownerId, clientId: next.clientId, txnId: next.id });
    const stored = await ctx.store.getTransaction(tx.id);
    if (!stored) throw new OAuthError(404, 'invalid_transaction');
    current = effective(ctx, stored);
  }
}

/** Step 10 of Section 6.3: the outstanding gates and the status they lead to. */
async function gates(ctx: IssuerContext, tx: Transaction, client: Client, shareOwner: boolean, ownerId: string): Promise<{ next: Transaction; grantConsent: boolean }> {
  const next = { ...tx };
  const wantsOwner = next.scopes.some((s) => OWNER_SCOPES.includes(s));
  if (wantsOwner) {
    // Section 6.6: a requested Owner Claim that cannot be issued for this Owner ends the sign-in; it is never omitted.
    const owner = await ctx.store.getOwner(ownerId);
    if (!owner || !ownerClaimsAvailable(owner, next.scopes)) return { next: ended(ctx, next, 'denied', 'access_denied'), grantConsent: false };
  }
  next.ownerApprovalOutstanding = wantsOwner && !shareOwner;
  const consent = await ctx.store.getConsent(next.handle!, next.clientId);
  const { record, forced } = reviewReasons(ctx, next, client, consent);
  if (record === 'expired') await ctx.store.deleteConsent(next.handle!, next.clientId); // Section 6.4: unused for T_CONSENT
  // accept_disclosure answers for the Consent Record only; a review that the request or the client demands stays due.
  const recordOutstanding = record !== null && !next.acceptDisclosure;
  next.reviewOutstanding = recordOutstanding || forced !== null;
  next.consentReason = (recordOutstanding ? record : forced) ?? undefined;
  next.consentRelied = consent !== undefined && record === null;
  if (next.prompt === 'none' && next.reviewOutstanding) return { next: ended(ctx, next, 'denied', 'consent_required'), grantConsent: false };
  if (next.prompt === 'none' && next.ownerApprovalOutstanding) return { next: ended(ctx, next, 'denied', 'interaction_required'), grantConsent: false };
  if (next.ownerApprovalOutstanding) {
    next.status = 'awaiting_owner';
    next.expiresAt = Math.max(next.expiresAt, next.createdAt + ctx.constants.T_OWNER); // Section 6.6
  } else if (next.reviewOutstanding) next.status = 'awaiting_consent';
  else next.status = 'ready';
  return { next, grantConsent: next.acceptDisclosure && !next.reviewOutstanding };
}

/** Section 6.4: the review decision, authorised by the transaction_token only. Returns the transaction as changed. */
export async function review(ctx: IssuerContext, loaded: Transaction, client: Client, viewer: Viewer, body: unknown): Promise<Transaction> {
  requireTransactionToken(viewer); // the session binding does not authorise this step
  for (let current = loaded; ; ) {
    requireOpen(current);
    if (current.status !== 'awaiting_consent') throw new OAuthError(400, 'invalid_request', 'no review is outstanding');
    if (!isPlainObject(body) || (body.decision !== 'allow' && body.decision !== 'deny')) throw new OAuthError(400, 'invalid_request', 'decision must be allow or deny');
    const allow = body.decision === 'allow';
    const next: Transaction = allow
      ? { ...current, reviewOutstanding: false, status: current.ownerApprovalOutstanding ? 'awaiting_owner' : 'ready' }
      : ended(ctx, current, 'denied', 'cancelled');
    if (await commit(ctx, next, current.version)) {
      await afterCommit(ctx, next, client, { grantConsent: allow });
      return next;
    }
    current = await reload(ctx, loaded.id);
  }
}

/** Section 6.6: the Owner's decision, given with an Owner Credential of the asserting Agent's Owner. */
export async function ownerDecision(ctx: IssuerContext, loaded: Transaction, client: Client, ownerId: string, decision: unknown): Promise<Transaction> {
  for (let current = loaded; ; ) {
    requireOpen(current);
    if (current.status !== 'awaiting_owner') throw new OAuthError(400, 'invalid_request', 'no approval is outstanding');
    if (current.ownerId !== ownerId) throw new OAuthError(404, 'invalid_transaction');
    if (decision !== 'approve' && decision !== 'refuse') throw new OAuthError(400, 'invalid_request', 'decision must be approve or refuse');
    const next: Transaction = decision === 'refuse'
      ? ended(ctx, current, 'denied', 'owner_declined')
      : { ...current, ownerApprovalOutstanding: false, status: current.reviewOutstanding ? 'awaiting_consent' : 'ready' };
    if (await commit(ctx, next, current.version)) {
      await afterCommit(ctx, next, client);
      return next;
    }
    current = await reload(ctx, loaded.id);
  }
}

async function reload(ctx: IssuerContext, id: string): Promise<Transaction> {
  const stored = await ctx.store.getTransaction(id);
  if (!stored) throw new OAuthError(404, 'invalid_transaction');
  return effective(ctx, stored);
}

export interface ContinueResult { redirect: string }

/**
 * Section 6.5: follow the continue URL. For `ready`, the transaction becomes `completed` by one conditional write and
 * only the request that made it issues the code: of several requests, at whatever issuer process, one receives a
 * code and the others `transaction_expired`.
 */
export async function cont(ctx: IssuerContext, loaded: Transaction, secret: string, viewer: Viewer): Promise<ContinueResult> {
  for (let tx = loaded; ; ) {
    const release = viewer.kind === 'transaction_token' || (viewer.kind === 'session' && tx.deliverToSession);
    if (!release) throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
    if (secret !== tx.continueSecret) throw new OAuthError(404, 'invalid_transaction');
    const u = new URL(tx.redirectUri);
    u.searchParams.set('state', tx.state);
    u.searchParams.set('iss', ctx.issuer);
    if (tx.status === 'completed') throw new OAuthError(410, 'transaction_expired');
    if (tx.status === 'denied' || tx.status === 'expired') {
      const { error, description } = redirectError(tx);
      u.searchParams.set('error', error);
      if (description) u.searchParams.set('error_description', description);
      return { redirect: u.href };
    }
    if (tx.status !== 'ready') throw new OAuthError(400, 'invalid_request', 'transaction is not ready');
    const next = { ...ended(ctx, tx, 'completed'), codeIssued: true };
    if (!(await commit(ctx, next, tx.version))) {
      tx = await loadTransaction(ctx, tx.id);
      continue;
    }
    // This request completed the transaction; it alone issues the code. Section 7.4: the Account is created or
    // updated now, counted once however many transactions complete for it together (Section 7.6).
    const code = randomSecret();
    await ctx.store.insertCode({
      hash: sha256(code),
      txnId: next.id,
      clientId: next.clientId,
      redirectUri: next.redirectUri,
      codeChallenge: next.codeChallenge,
      nonce: next.nonce,
      scopes: next.scopes,
      handle: next.handle!,
      kid: next.kid!,
      keyEnrollment: next.keyEnrollment!,
      authTime: next.assertedAt!,
      expiresAt: ctx.now() + ctx.constants.T_CODE,
      used: false,
      voided: false,
    });
    await ctx.store.recordSignIn({ handle: next.handle!, clientId: next.clientId, ownerId: next.ownerId!, txnId: next.id, now: ctx.now() });
    u.searchParams.set('code', code);
    return { redirect: u.href };
  }
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
