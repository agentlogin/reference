// The Agent Client (Section 1.2): completes Sign-in Transactions on behalf of one Agent.
// Conformance items A-1 to A-9 are referenced inline.
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { randomBytes } from 'node:crypto';
import { fetchMetadata, lookupIssuer, type DiscoveryOptions, type IssuerMetadata } from './discovery.js';
import { safeFetch } from './safefetch.js';
import { parseHandle, domainServed } from './handle.js';
import { MemoryCookieJar, type CookieJar } from './cookies.js';
import { MemoryKeystore, type Keystore, type StoredKey } from './keystore.js';

const rnd = (n = 16) => randomBytes(n).toString('base64url');
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, Number.isFinite(v) ? v : lo));

export interface TransactionResource {
  transaction_id: string;
  iss: string;
  url: string;
  status: 'awaiting_agent' | 'awaiting_owner' | 'awaiting_consent' | 'ready' | 'completed' | 'denied' | 'expired';
  next: { action: string; method?: string; url?: string; retry_after?: number };
  expires_at: number;
  client: { client_id: string; client_type: string; redirect_host: string; client_name?: string; logo_uri?: string; tos_uri?: string; policy_uri?: string };
  requested_scopes: string[];
  disclosure: Array<{ scope: string; title: string; description: string }>;
  challenge?: string;
  consent_reason?: string;
  reason?: string;
  login_hint?: string;
  requester?: { user_agent?: string; network?: string };
}
/** What callbacks receive: the transaction without its challenge, tokens or URLs. */
export interface TransactionView {
  transaction_id: string;
  iss: string;
  status: TransactionResource['status'];
  expires_at: number;
  client: TransactionResource['client'];
  requested_scopes: string[];
  disclosure: TransactionResource['disclosure'];
  consent_reason?: string;
  reason?: string;
  login_hint?: string;
  requester?: { user_agent?: string; network?: string };
}
const view = (t: TransactionResource): TransactionView => ({
  transaction_id: t.transaction_id, iss: t.iss, status: t.status, expires_at: t.expires_at, client: { ...t.client }, requested_scopes: [...(t.requested_scopes ?? [])],
  disclosure: (t.disclosure ?? []).map((d) => ({ ...d })), consent_reason: t.consent_reason, reason: t.reason, login_hint: t.login_hint, requester: t.requester ? { ...t.requester } : undefined,
});
/** Separates the bearer credentials from a parsed response so that they never travel with the resource. */
function parseResource(json: unknown): { tx: TransactionResource; sessionToken?: string; transactionToken?: string } | null {
  if (typeof json !== 'object' || json === null) return null;
  const { session_token, transaction_token, ...rest } = json as Record<string, unknown>;
  const tx = rest as unknown as TransactionResource;
  if (typeof tx.transaction_id !== 'string' || typeof tx.status !== 'string' || typeof tx.iss !== 'string' || typeof tx.url !== 'string') return null;
  if (typeof tx.client !== 'object' || tx.client === null || typeof tx.next !== 'object' || tx.next === null) return null;
  return { tx, sessionToken: typeof session_token === 'string' ? session_token : undefined, transactionToken: typeof transaction_token === 'string' ? transaction_token : undefined };
}

/** What an error may carry about a transaction: no challenge, tokens or URLs (Section 6 forbids those in logs and tool output). */
export interface TransactionSummary {
  transaction_id?: string;
  status?: string;
  reason?: string;
  consent_reason?: string;
  redirect_host?: string;
  client_id?: string;
  expires_at?: number;
}
function summarize(r: unknown): TransactionSummary | undefined {
  if (typeof r !== 'object' || r === null) return undefined;
  const t = r as Partial<TransactionResource>;
  if (typeof t.transaction_id !== 'string' && typeof t.status !== 'string') return undefined;
  return { transaction_id: t.transaction_id, status: t.status, reason: t.reason, consent_reason: t.consent_reason, redirect_host: t.client?.redirect_host, client_id: t.client?.client_id, expires_at: t.expires_at };
}

export class AgentLoginError extends Error {
  /** A redacted view of the transaction, safe to log. */
  public readonly resource?: TransactionSummary;
  constructor(message: string, public readonly code: string, public readonly status?: number, resource?: unknown) {
    super(message);
    this.name = 'AgentLoginError';
    this.resource = summarize(resource);
  }
}

/** One monotonic budget for discovery, redirects, callbacks and protocol requests. */
class SignInBudget {
  private readonly deadline: number;
  constructor(ms = 600_000) {
    if (!Number.isFinite(ms) || ms <= 0) throw this.timeout();
    this.deadline = performance.now() + ms;
  }
  private timeout() { return new AgentLoginError('sign-in did not finish before the deadline', 'timeout'); }
  left(): number {
    const ms = this.deadline - performance.now();
    if (ms <= 0) throw this.timeout();
    return Math.ceil(ms);
  }
  async run<T>(operation: () => Promise<T> | T): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(this.timeout()), this.left()); });
    try {
      const result = await Promise.race([Promise.resolve().then(() => { this.left(); return operation(); }), timeout]);
      this.left();
      return result;
    } catch (e) {
      this.left(); // an expired network exchange is reported consistently as timeout
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface AgentLoginOptions {
  handle: string;
  keystore?: Keystore;
  cookies?: CookieJar;
  /** Pin the Issuer instead of WebFinger discovery (development, or a known deployment). handle_domains is still checked. */
  issuer?: string;
  /** Development only: http issuers, loopback addresses. */
  allowInsecure?: boolean;
  /** Per-request timeout, default 10 s. */
  timeoutMs?: number;
  log?: (message: string) => void;
}
export interface SignInOptions {
  /** The Authentication Request URL the Relying Party produced (its "Sign in with your agent" link). */
  authorizationUrl: string;
  /** Host of the Relying Party the agent set out to sign in to; the transaction's client.redirect_host must equal it (A-3). */
  expectedHost?: string;
  /** Hosts accepted for expectedHost in addition to itself (for Relying Parties whose redirect URI lives on another host). */
  acceptHosts?: string[];
  /** Set only for development against untrusted clients: skips the redirect_host check. */
  unsafeSkipHostCheck?: boolean;
  /** Accept the disclosure in the assertion (skips the review when the Issuer permits). Default true. */
  acceptDisclosure?: boolean;
  /** Called when the Issuer requires a review; return 'allow' or 'deny'. Default: allow when acceptDisclosure, else deny. */
  onReview?: (transaction: TransactionView) => Promise<'allow' | 'deny'> | 'allow' | 'deny';
  /** Called once when the Owner must approve. */
  onOwnerApproval?: (transaction: TransactionView) => void;
  /** Overall sign-in deadline, including discovery, application redirects and callbacks; default 10 minutes. */
  deadlineMs?: number;
}
export interface SignInResult {
  handle: string;
  issuer: string;
  client: TransactionResource['client'];
  scopes: string[];
  /**
   * The code-bearing redirect URL. Keep it out of prompts, tool output and logs (A-9); pass the result to follow().
   * The property is non-enumerable, so JSON.stringify and console.log of the result do not show it.
   */
  readonly redirectUrl: string;
}
export interface FollowResult {
  status: number;
  /** Final URL without its query string: the callback's query carries the code. */
  url: string;
  body: string;
  headers: Headers;
}
export interface SignInAtOptions extends Omit<SignInOptions, 'authorizationUrl'> {
  /** Append `iss` and `login_hint` as Section 5.8 defines for an `initiate_login_uri`. Default true. */
  sendIssAndLoginHint?: boolean;
}

export class AgentLogin {
  readonly handle: string;
  private readonly keystore: Keystore;
  readonly cookies: CookieJar;
  private readonly disc: DiscoveryOptions;
  private located?: { issuer: string; until: number };

  constructor(private readonly opts: AgentLoginOptions) {
    const h = parseHandle(opts.handle);
    if (!h) throw new AgentLoginError(`not a handle: ${opts.handle}`, 'invalid_handle');
    this.handle = h.handle;
    this.keystore = opts.keystore ?? new MemoryKeystore();
    this.cookies = opts.cookies ?? new MemoryCookieJar();
    this.disc = { allowInsecure: opts.allowInsecure, timeoutMs: opts.timeoutMs };
  }
  static async open(opts: AgentLoginOptions): Promise<AgentLogin> {
    return new AgentLogin(opts);
  }
  private log(m: string) { this.opts.log?.(m); }

  /**
   * Section 2: the Home Issuer for this Agent (A-1). The WebFinger result and the metadata are each reused only for
   * as long as their responses allow (five minutes at most for the former within one process).
   */
  async discover(): Promise<{ issuer: string; metadata: IssuerMetadata }> {
    return this.discoverWithin();
  }
  private async discoverWithin(budget?: SignInBudget): Promise<{ issuer: string; metadata: IssuerMetadata }> {
    const options = () => ({ ...this.disc, timeoutMs: Math.min(this.disc.timeoutMs ?? 10_000, budget?.left() ?? Infinity) });
    const run = <T>(operation: () => Promise<T>) => budget ? budget.run(operation) : operation();
    try {
      let issuer: string;
      if (this.opts.issuer) issuer = this.opts.issuer;
      else if (this.located && Date.now() < this.located.until) issuer = this.located.issuer;
      else {
        const found = await run(() => lookupIssuer(this.handle, options()));
        issuer = found.issuer;
        this.located = { issuer, until: Date.now() + Math.min(found.maxAge, 300) * 1000 };
      }
      const metadata = await run(() => fetchMetadata(issuer, options()));
      if (this.opts.issuer) {
        const h = parseHandle(this.handle)!;
        if (!domainServed(h.domain, metadata.handle_domains)) throw new AgentLoginError(`${issuer} does not serve ${h.domain}`, 'issuer_mismatch');
      }
      return { issuer, metadata };
    } catch (e) {
      if (e instanceof AgentLoginError) throw e;
      throw new AgentLoginError(`could not find the Issuer for ${this.handle}: ${(e as Error).message}`, 'discovery_failed');
    }
  }

  // ---- keys (Section 7) ------------------------------------------------------------------------------
  async generateKey(name?: string): Promise<StoredKey> {
    const { issuer } = await this.discover();
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const priv = await exportJWK(privateKey);
    const pub = await exportJWK(publicKey);
    const publicJwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
    const key: StoredKey = { kid: await calculateJwkThumbprint(publicJwk, 'sha256'), handle: this.handle, issuer, privateJwk: priv, publicJwk, name, createdAt: Math.floor(Date.now() / 1000), status: 'pending' };
    await this.keystore.put(key);
    return key;
  }
  /**
   * Section 7.2: enroll a new key with an Owner or Delegated Credential and prove possession.
   *
   * The private key is deleted only when the Issuer has definitely refused it. When an answer is lost (a timeout, a
   * gateway error, an unreadable body), the Issuer may have enrolled the key all the same: the client then asks the
   * Issuer what it has and, if it cannot find out, keeps the key and reports `enrollment_uncertain`; `reconcileKeys`
   * settles it later.
   */
  async enroll(p: { credential: string; name?: string; expiresAt?: number }): Promise<StoredKey> {
    const { issuer, metadata } = await this.discover();
    const key = await this.generateKey(p.name);
    const refused = async (e: AgentLoginError): Promise<never> => {
      await this.keystore.remove(key.kid);
      throw e;
    };
    const unknown = async (cause: string): Promise<StoredKey> => {
      const state = await this.remoteKeyState(p.credential, key.kid);
      if (state.status === 'active') return this.markActive(key, state.expiresAt);
      if (state.status === 'absent' || state.status === 'dead') return refused(new AgentLoginError(`enrollment failed: ${cause}`, 'enrollment_failed'));
      throw new AgentLoginError(`the outcome of the enrollment is not known (${cause}); the key is kept, run reconcileKeys to settle it`, 'enrollment_uncertain');
    };
    /** A 4xx with an error body is the Issuer's decision; anything else is an answer that did not arrive. */
    const definite = (r: { status: number; json: unknown }) => r.status >= 400 && r.status < 500 && typeof (r.json as { error?: unknown } | undefined)?.error === 'string';

    const base = `${metadata.agents_endpoint}/${encodeURIComponent(this.handle)}/keys`;
    let en;
    try {
      en = await this.json(base, { method: 'POST', headers: { authorization: `Bearer ${p.credential}` }, body: { jwk: key.publicJwk, name: p.name, expires_at: p.expiresAt } });
    } catch (e) {
      return unknown((e as Error).message);
    }
    if (definite(en)) return refused(this.error('enrollment refused', en));
    const rec = en.json as { challenge?: unknown; proof_url?: unknown; kid?: unknown; expires_at?: unknown } | undefined;
    if (en.status !== 201 || typeof rec?.challenge !== 'string' || typeof rec.proof_url !== 'string') return unknown(`the Issuer answered ${en.status}`);
    if (rec.kid !== key.kid) return refused(new AgentLoginError('issuer computed a different kid', 'kid_mismatch'));
    try {
      this.assertUnder(rec.proof_url, metadata.agents_endpoint);
    } catch (e) {
      return refused(e as AgentLoginError);
    }
    const now = Math.floor(Date.now() / 1000);
    const proof = await new SignJWT({ nonce: rec.challenge, jti: rnd() })
      .setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid })
      .setIssuer(this.handle).setSubject(this.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60)
      .sign(await importJWK(key.privateJwk, 'ES256'));
    let pr;
    try {
      pr = await this.json(rec.proof_url, { method: 'POST', body: { proof } });
    } catch (e) {
      return unknown((e as Error).message);
    }
    if (pr.status === 200) return this.markActive(key, typeof rec.expires_at === 'number' ? rec.expires_at : undefined);
    if (definite(pr)) return refused(this.error('enrollment proof refused', pr));
    return unknown(`the Issuer answered ${pr.status} to the proof`);
  }
  private async markActive(key: StoredKey, expiresAt?: number): Promise<StoredKey> {
    const active: StoredKey = { ...key, status: 'active', ...(expiresAt !== undefined ? { expiresAt } : {}) };
    await this.keystore.put(active);
    return active;
  }
  /** What the Issuer holds for a key of this Agent: `unknown` when it cannot be asked. */
  private async remoteKeyState(credential: string, kid: string): Promise<{ status: 'active' | 'pending' | 'dead' | 'absent' | 'unknown'; expiresAt?: number }> {
    const { metadata } = await this.discover();
    let r;
    try {
      r = await this.json(`${metadata.agents_endpoint}/${encodeURIComponent(this.handle)}/keys/${encodeURIComponent(kid)}`, { headers: { authorization: `Bearer ${credential}` } });
    } catch {
      return { status: 'unknown' };
    }
    if (r.status === 404) return { status: 'absent' };
    const rec = r.json as { status?: unknown; expires_at?: unknown } | undefined;
    if (r.status !== 200 || typeof rec?.status !== 'string') return { status: 'unknown' };
    const expiresAt = typeof rec.expires_at === 'number' ? rec.expires_at : undefined;
    if (rec.status === 'active' || rec.status === 'pending') return { status: rec.status, expiresAt };
    return { status: 'dead' };
  }
  /**
   * Settles local keys of this Agent at this Issuer whose enrollment outcome was not known: one the Issuer holds as
   * active becomes usable, one it does not hold or holds as revoked or expired is removed, one it still holds as
   * pending is left for a later call (the Issuer drops it if it is never proved).
   */
  async reconcileKeys(credential: string): Promise<{ activated: number; removed: number; pending: number }> {
    const { issuer } = await this.discover();
    const out = { activated: 0, removed: 0, pending: 0 };
    for (const k of await this.keystore.list(this.handle)) {
      if (k.status !== 'pending' || k.issuer !== issuer) continue;
      const state = await this.remoteKeyState(credential, k.kid);
      if (state.status === 'active') { await this.markActive(k, state.expiresAt); out.activated += 1; }
      else if (state.status === 'absent' || state.status === 'dead') { await this.keystore.remove(k.kid); out.removed += 1; }
      else out.pending += 1;
    }
    return out;
  }
  async activeKey(): Promise<StoredKey> {
    const { issuer } = await this.discover();
    return this.keyForIssuer(issuer);
  }
  private async keyForIssuer(issuer: string): Promise<StoredKey> {
    const now = Math.floor(Date.now() / 1000);
    const keys = (await this.keystore.list(this.handle)).filter((k) => k.status === 'active' && k.issuer === issuer && (k.expiresAt === undefined || k.expiresAt > now + 60));
    if (keys.length === 0) throw new AgentLoginError(`no usable key for ${this.handle} at ${issuer}; enroll one first`, 'no_key');
    return keys.sort((a, b) => b.createdAt - a.createdAt)[0]!;
  }
  async listKeys(credential: string): Promise<unknown> {
    const { metadata } = await this.discover();
    const r = await this.json(`${metadata.agents_endpoint}/${encodeURIComponent(this.handle)}/keys`, { headers: { authorization: `Bearer ${credential}` } });
    if (r.status !== 200) throw this.error('listing keys failed', r);
    return r.json;
  }
  async revokeKey(credential: string, kid?: string): Promise<void> {
    const { metadata } = await this.discover();
    const base = `${metadata.agents_endpoint}/${encodeURIComponent(this.handle)}/keys`;
    const r = await this.json(kid ? `${base}/${encodeURIComponent(kid)}` : base, { method: 'DELETE', headers: { authorization: `Bearer ${credential}` } });
    if (r.status !== 204) throw this.error('revocation failed', r);
    const { issuer } = await this.discover();
    // Only the records of this Issuer: the same handle may hold keys at another one.
    for (const k of await this.keystore.list(this.handle)) if (k.issuer === issuer && (!kid || k.kid === kid)) await this.keystore.put({ ...k, status: 'revoked' });
  }

  // ---- sign-in (Sections 5, 6) -------------------------------------------------------------------------
  async signIn(o: SignInOptions): Promise<SignInResult> {
    return this.signInWithin(o, new SignInBudget(o.deadlineMs));
  }
  private async signInWithin(o: SignInOptions, budget: SignInBudget, discovered?: { issuer: string; metadata: IssuerMetadata }): Promise<SignInResult> {
    const left = () => budget.left();
    const ask = (url: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) =>
      budget.run(() => this.json(url, { ...init, timeoutMs: left() }));
    const pause = (ms: number) => budget.run(() => sleep(Math.min(ms, left())));
    // Everything that can be decided locally is decided before the Issuer is asked to create a transaction.
    if (!o.unsafeSkipHostCheck && !o.expectedHost) throw new AgentLoginError('expectedHost is required: the host of the application you are signing in to', 'expected_host_required');
    let authUrl: URL;
    try {
      authUrl = new URL(o.authorizationUrl);
    } catch {
      throw new AgentLoginError('authorizationUrl is not a URL', 'invalid_request');
    }
    const { issuer, metadata } = discovered ?? await this.discoverWithin(budget);
    // A transaction this client starts itself (Section 6.3): its own Authentication Request, sent to the published
    // authorization_endpoint and answered on the JSON path of Section 5.3. Any other URL at the Issuer, for example a
    // Transaction Resource someone else started, is refused, and so is a response without a session_token.
    const ae = new URL(metadata.authorization_endpoint);
    if (authUrl.origin !== ae.origin || authUrl.pathname !== ae.pathname || authUrl.username || authUrl.password) {
      throw new AgentLoginError(`not the authorization endpoint of this Agent's Issuer (${issuer})`, 'wrong_issuer');
    }
    const key = await budget.run(() => this.keyForIssuer(issuer));
    const start = await ask(authUrl.href);
    if (start.status >= 300 && start.status < 400) throw new AgentLoginError('the Issuer answered with a redirect: it does not offer the JSON response of Section 5.3', 'protocol_error', start.status);
    if (start.status !== 200) throw this.error('the Issuer refused the Authentication Request', start);
    const started = parseResource(start.json);
    if (!started || !started.sessionToken) {
      throw new AgentLoginError('the Issuer did not answer with the Transaction Resource of Section 5.3; this client did not start this transaction', 'protocol_error', start.status);
    }
    let tx = started.tx;
    this.check(tx, issuer, metadata, o);
    if (tx.status !== 'awaiting_agent' || tx.next.action !== 'assert' || typeof tx.challenge !== 'string' || !tx.next.url) throw new AgentLoginError(`unexpected initial status ${tx.status}`, 'unexpected_status', undefined, tx);

    // Section 6.3: the assertion. deliver_to_session is never set: this client is itself the Session Holder (A-4).
    const now = Math.floor(Date.now() / 1000);
    const assertion = await budget.run(async () => new SignJWT({ txn: tx.transaction_id, nonce: tx.challenge, jti: rnd(), accept_disclosure: o.acceptDisclosure !== false })
      .setProtectedHeader({ alg: 'ES256', typ: 'agent-login+jwt', kid: key.kid })
      .setIssuer(this.handle).setSubject(this.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60)
      .sign(await importJWK(key.privateJwk, 'ES256')));
    const a = await ask(tx.next.url, { method: 'POST', body: { assertion } });
    if (a.status !== 200) {
      const code = (a.json as { error?: string } | undefined)?.error;
      // unknown_key can reflect interrupted Agent authority (for example disable/re-enable), not revocation
      // of this enrollment. Keep the key available for a fresh sign-in unless revocation is explicit.
      if (code === 'key_revoked') await this.keystore.put({ ...key, status: 'revoked' });
      throw this.error('assertion refused', a);
    }
    const asserted = parseResource(a.json);
    if (!asserted || !asserted.transactionToken) throw new AgentLoginError('no transaction_token returned', 'protocol_error', 200, a.json);
    tx = asserted.tx;
    const bearer = { authorization: `Bearer ${asserted.transactionToken}` };
    const next = (json: unknown, what: string): TransactionResource => {
      const r = parseResource(json);
      if (!r) throw new AgentLoginError(`${what}: the Issuer did not return a Transaction Resource`, 'protocol_error');
      return r.tx;
    };
    let notified = false;

    // A-5, A-8: act on status and next only, until the deadline.
    for (;;) {
      this.check(tx, issuer, metadata, o);
      if (tx.status === 'ready') break;
      if (tx.status === 'denied' || tx.status === 'expired') throw new AgentLoginError(`sign-in ${tx.status}${tx.reason ? ` (${tx.reason})` : ''}`, tx.reason ?? tx.status, undefined, tx);
      if (tx.status === 'completed') throw new AgentLoginError('transaction already completed', 'completed', undefined, tx);
      left();
      if (tx.status === 'awaiting_consent') {
        if (!tx.next.url) throw new AgentLoginError('review step without a URL', 'protocol_error', undefined, tx);
        const decision = o.onReview ? await budget.run(() => o.onReview!(view(tx))) : o.acceptDisclosure === false ? 'deny' : 'allow';
        this.log(`review (${tx.consent_reason}): ${decision}`);
        const r = await ask(tx.next.url, { method: 'POST', headers: bearer, body: { decision } });
        if (r.status !== 200) throw this.error('review refused', r);
        tx = next(r.json, 'review');
        continue;
      }
      if (tx.status === 'awaiting_owner') {
        if (!notified) {
          notified = true;
          if (o.onOwnerApproval) o.onOwnerApproval(view(tx));
          else this.log('waiting for the Owner to approve');
        }
        if (Date.now() / 1000 > tx.expires_at) throw new AgentLoginError('the transaction expired while waiting for the Owner', 'timeout', undefined, tx);
        await pause(clamp(tx.next.retry_after ?? 5, 1, 60) * 1000);
        const g = await ask(tx.url, { headers: bearer });
        if (g.status === 429) { // Section 6.7: honour Retry-After, then poll again
          await pause(clamp(Number(g.retryAfter) || 5, 1, 60) * 1000);
          continue;
        }
        if (g.status !== 200) throw this.error('polling failed', g);
        tx = next(g.json, 'polling'); // expires_at is re-read on every poll (Section 6.6)
        continue;
      }
      throw new AgentLoginError(`unexpected status ${tx.status}`, 'unexpected_status', undefined, tx);
    }
    // Section 6.5: the continue step, with the transaction_token (A-6). Never with the session credential and
    // never followed when deliver_to_session was set (it never is here).
    if (!tx.next.url) throw new AgentLoginError('continue URL withheld', 'protocol_error', undefined, tx);
    const c = await ask(tx.next.url, { headers: bearer }); // checked against the deadline like every other step
    let redirectUrl: string | undefined;
    if (c.status === 200 && typeof (c.json as { redirect?: unknown } | undefined)?.redirect === 'string') redirectUrl = (c.json as { redirect: string }).redirect;
    else if ((c.status === 302 || c.status === 303) && c.location) redirectUrl = c.location; // an Issuer that answered the HTML form
    if (!redirectUrl) throw this.error('continue failed', c);
    let rh: URL;
    try {
      rh = new URL(redirectUrl);
    } catch {
      throw new AgentLoginError('the Issuer returned a malformed redirect', 'protocol_error');
    }
    if (rh.host !== tx.client.redirect_host) throw new AgentLoginError('redirect does not go to the client host', 'protocol_error');
    const result = { handle: this.handle, issuer, client: tx.client, scopes: tx.requested_scopes } as SignInResult;
    Object.defineProperty(result, 'redirectUrl', { value: redirectUrl, enumerable: false });
    return result;
  }

  /**
   * Section 5.8: start at the application. `loginUrl` is its `initiate_login_uri` (or any URL of the application that
   * redirects to the Authentication Request); `iss` and `login_hint` are appended. The application's cookies are
   * kept in the cookie jar, so an application that binds `state` to a cookie can complete the callback in follow().
   */
  async signInAt(loginUrl: string, o: SignInAtOptions = {}): Promise<SignInResult> {
    const budget = new SignInBudget(o.deadlineMs);
    const discovered = await this.discoverWithin(budget);
    const { issuer, metadata } = discovered;
    let url: URL;
    try {
      url = new URL(loginUrl);
    } catch {
      throw new AgentLoginError('loginUrl is not a URL', 'invalid_request');
    }
    if (url.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('loginUrl is not https', 'insecure_url');
    const site = url.host;
    if (o.sendIssAndLoginHint !== false) {
      url.searchParams.set('iss', issuer);
      url.searchParams.set('login_hint', this.handle);
    }
    const ae = new URL(metadata.authorization_endpoint);
    for (let hop = 0; hop < 5; hop += 1) {
      const res = await this.rpFetch(url, {}, budget);
      await budget.run(() => res.arrayBuffer());
      const location = res.headers.get('location');
      if (!(res.status >= 300 && res.status < 400) || !location) {
        throw new AgentLoginError(`the application did not redirect to a sign-in (status ${res.status})`, 'no_authorization_request', res.status);
      }
      const next = new URL(location, url);
      if (next.origin === ae.origin && next.pathname === ae.pathname) {
        return this.signInWithin({ ...o, authorizationUrl: next.href, expectedHost: o.expectedHost ?? site }, budget, discovered);
      }
      if (next.host !== site) throw new AgentLoginError(`the application redirected to ${next.host}, which is not this Agent's Issuer`, 'wrong_issuer');
      if (next.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('redirect is not https', 'insecure_redirect');
      url = next;
    }
    throw new AgentLoginError('too many redirects at the application', 'no_authorization_request');
  }

  /**
   * Fetches the code-bearing redirect with the cookie jar for that host and follows redirects within that host.
   * No Authorization header is sent (A-9). The returned URL never includes a query string.
   */
  async follow(result: SignInResult, maxRedirects = 5): Promise<FollowResult> {
    let url = new URL(result.redirectUrl);
    const host = url.host;
    if (url.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('redirect is not https', 'insecure_redirect');
    for (let i = 0; ; i += 1) {
      const res = await this.rpFetch(url);
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location) {
        const next = new URL(location, url);
        await res.arrayBuffer();
        if (i >= maxRedirects) throw new AgentLoginError('too many redirects at the application after the callback', 'callback_failed', res.status);
        if (next.protocol === 'http:' && url.protocol === 'https:') throw new AgentLoginError('redirect downgraded to http', 'insecure_redirect');
        if (next.host !== host) return { status: res.status, url: `${url.origin}${url.pathname}`, body: '', headers: res.headers }; // do not leave the application
        url = next;
        continue;
      }
      return { status: res.status, url: `${url.origin}${url.pathname}`, body: await res.text(), headers: res.headers };
    }
  }
  /** A request to the application with the stored session cookies. Redirects are not followed. */
  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    return this.rpFetch(new URL(url), init);
  }
  /** One request to a Relying Party: jar cookies in, Set-Cookie stored, no redirect following, bounded in time. */
  private async rpFetch(u: URL, init: RequestInit = {}, budget?: SignInBudget): Promise<Response> {
    const run = <T>(operation: () => Promise<T>) => budget ? budget.run(operation) : operation();
    if (u.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('non-https URL', 'insecure_url');
    const cookie = await run(() => this.cookies.header(u));
    const headers = new Headers(init.headers);
    if (!headers.has('accept')) headers.set('accept', 'text/html, application/json;q=0.9, */*;q=0.1');
    if (cookie) headers.set('cookie', cookie);
    headers.delete('authorization');
    let res: Response;
    try {
      const timeout = AbortSignal.timeout(Math.min(this.opts.timeoutMs ?? 10_000, budget?.left() ?? Infinity));
      const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
      res = await run(() => fetch(u, { ...init, headers, redirect: 'manual', signal }));
    } catch (e) {
      if (e instanceof AgentLoginError && e.code === 'timeout') throw e;
      throw new AgentLoginError(`request to ${u.host} failed: ${(e as Error).message}`, 'network_error');
    }
    await run(() => this.cookies.store(u, res.headers.getSetCookie()));
    return res;
  }

  // ---- helpers ------------------------------------------------------------------------------------------
  /** A-3: the resource must come from this Agent's Issuer and point into its transaction endpoint; the client must be the one the agent set out to sign in to. */
  private check(tx: TransactionResource, issuer: string, m: IssuerMetadata, o: SignInOptions) {
    if (tx.iss !== issuer) throw new AgentLoginError(`transaction iss ${tx.iss} is not ${issuer}`, 'wrong_issuer', undefined, tx);
    const action = { awaiting_agent: 'assert', awaiting_owner: 'await_owner', awaiting_consent: 'review', ready: 'continue',
      completed: 'none', denied: 'continue', expired: 'continue' }[tx.status];
    if (!action || tx.next?.action !== action) throw new AgentLoginError('transaction status and next action disagree', 'protocol_error', undefined, tx);
    this.assertUnder(tx.url, m.transaction_endpoint);
    if (tx.next?.url && tx.next.action !== 'none') this.assertUnder(tx.next.url, m.transaction_endpoint);
    if (typeof tx.client?.redirect_host !== 'string') throw new AgentLoginError('transaction without client.redirect_host', 'protocol_error');
    if (!o.unsafeSkipHostCheck) {
      const ok = [o.expectedHost!, ...(o.acceptHosts ?? [])].map((h) => h.toLowerCase());
      if (!ok.includes(tx.client.redirect_host.toLowerCase())) throw new AgentLoginError(`this sign-in is for ${tx.client.redirect_host}, not ${o.expectedHost}`, 'unexpected_client', undefined, tx);
    }
  }
  /** `url` must lie under `base`: same origin, and the same path or a descendant of it, after URL normalisation. */
  private assertUnder(url: string, base: string) {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      throw new AgentLoginError('malformed URL from the Issuer', 'protocol_error');
    }
    const b = new URL(base);
    const basePath = b.pathname.replace(/\/$/, '');
    if (u.origin !== b.origin || u.username || u.password || u.hash || !(u.pathname === basePath || u.pathname.startsWith(`${basePath}/`))) {
      throw new AgentLoginError(`a URL from the Issuer is not under ${base}`, 'wrong_issuer');
    }
    if (u.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('non-https URL from the Issuer', 'insecure_url');
  }
  /** One request to the Issuer: no cookies, no redirects, the fetch protections of Section 2.2, bounded in time and size. */
  private async json(url: string, init: { method?: string; headers?: Record<string, string>; body?: unknown; timeoutMs?: number } = {}): Promise<{ status: number; json: unknown; text: string; retryAfter?: string; location?: string }> {
    const headers: Record<string, string> = { ...init.headers };
    let body: string | undefined;
    if (init.body !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(init.body); }
    let res;
    try {
      res = await safeFetch(url, { method: init.method ?? 'GET', headers, body, accept: 'application/json', maxBytes: 64 * 1024, timeoutMs: Math.max(1, Math.min(this.opts.timeoutMs ?? 10_000, init.timeoutMs ?? Infinity)), allowPrivate: this.opts.allowInsecure, maxRedirects: 0 });
    } catch (e) {
      throw new AgentLoginError(`request to the Issuer failed: ${(e as Error).message}`, 'network_error');
    }
    const text = res.body.toString('utf8');
    let json: unknown;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    const h = (k: string) => { const v = res.headers[k]; return Array.isArray(v) ? v[0] : v; };
    return { status: res.status, json, text, retryAfter: h('retry-after'), location: h('location') };
  }
  private error(what: string, r: { status: number; json: unknown; text: string }): AgentLoginError {
    const j = (r.json ?? {}) as { error?: string; error_description?: string; status?: string; reason?: string };
    return new AgentLoginError(`${what}: ${r.status} ${j.error ?? ''}${j.error_description ? ` (${j.error_description})` : ''}`.trim(), j.error ?? `http_${r.status}`, r.status, r.json);
  }
}
