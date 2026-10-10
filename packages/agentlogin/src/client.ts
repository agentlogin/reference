// The Agent Client (Section 1.2): completes Sign-in Transactions on behalf of one Agent.
// Conformance items A-1 to A-9 are referenced inline.
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { randomBytes } from 'node:crypto';
import { discover, fetchMetadata, type DiscoveryOptions, type IssuerMetadata } from './discovery.js';
import { parseHandle, domainServed } from './handle.js';
import { MemoryCookieJar, type CookieJar } from './cookies.js';
import { MemoryKeystore, type Keystore, type StoredKey } from './keystore.js';

const rnd = (n = 16) => randomBytes(n).toString('base64url');

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
  session_token?: string;
  transaction_token?: string;
  [k: string]: unknown;
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
  onReview?: (resource: TransactionResource) => Promise<'allow' | 'deny'> | 'allow' | 'deny';
  /** Called once when the Owner must approve. */
  onOwnerApproval?: (resource: TransactionResource) => void;
  /** Overall deadline for waiting states, default 10 minutes. */
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
  private resolved?: { issuer: string; metadata: IssuerMetadata };

  constructor(private readonly opts: AgentLoginOptions) {
    const h = parseHandle(opts.handle);
    if (!h) throw new AgentLoginError(`not a handle: ${opts.handle}`, 'invalid_handle');
    this.handle = h.handle;
    this.keystore = opts.keystore ?? new MemoryKeystore();
    this.cookies = opts.cookies ?? new MemoryCookieJar();
    this.disc = { allowInsecure: opts.allowInsecure };
  }
  static async open(opts: AgentLoginOptions): Promise<AgentLogin> {
    return new AgentLogin(opts);
  }
  private log(m: string) { this.opts.log?.(m); }

  /** Section 2: the Home Issuer for this Agent (A-1). */
  async discover(): Promise<{ issuer: string; metadata: IssuerMetadata }> {
    if (this.resolved) return this.resolved;
    if (this.opts.issuer) {
      const issuer = this.opts.issuer.replace(/\/$/, '');
      const metadata = await fetchMetadata(issuer, this.disc);
      const h = parseHandle(this.handle)!;
      if (!domainServed(h.domain, metadata.handle_domains)) throw new AgentLoginError(`${issuer} does not serve ${h.domain}`, 'issuer_mismatch');
      this.resolved = { issuer, metadata };
    } else {
      this.resolved = await discover(this.handle, this.disc);
    }
    return this.resolved;
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
  /** Section 7.2: enroll a new key with an Owner or Delegated Credential and prove possession. */
  async enroll(p: { credential: string; name?: string; expiresAt?: number }): Promise<StoredKey> {
    const { issuer, metadata } = await this.discover();
    const key = await this.generateKey(p.name);
    const base = `${metadata.agents_endpoint}/${encodeURIComponent(this.handle)}/keys`;
    const en = await this.json(base, { method: 'POST', headers: { authorization: `Bearer ${p.credential}` }, body: { jwk: key.publicJwk, name: p.name, expires_at: p.expiresAt } });
    if (en.status !== 201) throw this.error('enrollment refused', en);
    const rec = en.json as { challenge: string; proof_url: string; kid: string };
    if (rec.kid !== key.kid) throw new AgentLoginError('issuer computed a different kid', 'kid_mismatch');
    this.assertUnder(rec.proof_url, metadata.agents_endpoint);
    const now = Math.floor(Date.now() / 1000);
    const proof = await new SignJWT({ nonce: rec.challenge, jti: rnd() })
      .setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid })
      .setIssuer(this.handle).setSubject(this.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60)
      .sign(await importJWK(key.privateJwk, 'ES256'));
    const pr = await this.json(rec.proof_url, { method: 'POST', body: { proof } });
    if (pr.status !== 200) throw this.error('enrollment proof refused', pr);
    key.status = 'active';
    await this.keystore.put(key);
    return key;
  }
  async activeKey(): Promise<StoredKey> {
    const { issuer } = await this.discover();
    const keys = (await this.keystore.list(this.handle)).filter((k) => k.status === 'active' && k.issuer === issuer);
    if (keys.length === 0) throw new AgentLoginError(`no active key for ${this.handle} at ${issuer}; run enroll first`, 'no_key');
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
    for (const k of await this.keystore.list(this.handle)) if (!kid || k.kid === kid) await this.keystore.put({ ...k, status: 'revoked' });
  }

  // ---- sign-in (Sections 5, 6) -------------------------------------------------------------------------
  async signIn(o: SignInOptions): Promise<SignInResult> {
    const { issuer, metadata } = await this.discover();
    let authUrl: URL;
    try {
      authUrl = new URL(o.authorizationUrl);
    } catch {
      throw new AgentLoginError('authorizationUrl is not a URL', 'invalid_request');
    }
    // A transaction this client starts itself (Section 6.3): its own Authentication Request, sent to the published
    // authorization_endpoint and answered on the JSON path of Section 5.3. Any other URL at the Issuer, for example a
    // Transaction Resource someone else started, is refused, and so is a response without a session_token.
    const ae = new URL(metadata.authorization_endpoint);
    if (authUrl.origin !== ae.origin || authUrl.pathname !== ae.pathname || authUrl.username || authUrl.password) {
      throw new AgentLoginError(`not the authorization endpoint of this Agent's Issuer (${issuer})`, 'wrong_issuer');
    }
    const start = await this.json(authUrl.href, { headers: { accept: 'application/json' } });
    if (start.status !== 200) throw this.error('the Issuer refused the Authentication Request', start);
    let tx = start.json as TransactionResource;
    if (typeof tx !== 'object' || tx === null || typeof tx.session_token !== 'string' || typeof tx.transaction_id !== 'string' || typeof tx.client !== 'object' || tx.client === null) {
      throw new AgentLoginError('the Issuer did not answer with the Transaction Resource of Section 5.3; this client did not start this transaction', 'protocol_error', start.status);
    }
    this.check(tx, issuer, metadata, o);
    const key = await this.activeKey();
    if (tx.status !== 'awaiting_agent' || tx.next.action !== 'assert' || !tx.challenge || !tx.next.url) throw new AgentLoginError(`unexpected initial status ${tx.status}`, 'unexpected_status', undefined, tx);

    // Section 6.3: the assertion. deliver_to_session is never set: this client is itself the Session Holder (A-4).
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ txn: tx.transaction_id, nonce: tx.challenge, jti: rnd(), accept_disclosure: o.acceptDisclosure !== false })
      .setProtectedHeader({ alg: 'ES256', typ: 'agent-login+jwt', kid: key.kid })
      .setIssuer(this.handle).setSubject(this.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60)
      .sign(await importJWK(key.privateJwk, 'ES256'));
    const a = await this.json(tx.next.url, { method: 'POST', body: { assertion } });
    if (a.status !== 200) throw this.error('assertion refused', a);
    tx = a.json as TransactionResource;
    const token = tx.transaction_token;
    if (!token) throw new AgentLoginError('no transaction_token returned', 'protocol_error', 200, tx);
    const bearer = { authorization: `Bearer ${token}` };
    const deadline = Date.now() + (o.deadlineMs ?? 600_000);
    let notified = false;

    // A-5, A-8: act on status and next only.
    for (;;) {
      this.check(tx, issuer, metadata, o);
      if (tx.status === 'ready') break;
      if (tx.status === 'denied' || tx.status === 'expired') throw new AgentLoginError(`sign-in ${tx.status}${tx.reason ? ` (${tx.reason})` : ''}`, tx.reason ?? tx.status, undefined, tx);
      if (tx.status === 'completed') throw new AgentLoginError('transaction already completed', 'completed', undefined, tx);
      if (tx.status === 'awaiting_consent') {
        const decision = o.onReview ? await o.onReview(tx) : o.acceptDisclosure === false ? 'deny' : 'allow';
        this.log(`review (${tx.consent_reason}): ${decision}`);
        const r = await this.json(tx.next.url!, { method: 'POST', headers: bearer, body: { decision } });
        if (r.status !== 200) throw this.error('review refused', r);
        tx = r.json as TransactionResource;
        continue;
      }
      if (tx.status === 'awaiting_owner') {
        if (!notified) { notified = true; o.onOwnerApproval?.(tx); this.log('waiting for the Owner to approve'); }
        if (Date.now() > deadline || Date.now() / 1000 > tx.expires_at) throw new AgentLoginError('timed out waiting for the Owner', 'timeout', undefined, tx);
        await new Promise((r) => setTimeout(r, Math.max(1, tx.next.retry_after ?? 5) * 1000));
        const g = await this.json(tx.url, { headers: bearer });
        if (g.status !== 200) throw this.error('polling failed', g);
        tx = g.json as TransactionResource;
        continue;
      }
      throw new AgentLoginError(`unexpected status ${tx.status}`, 'unexpected_status', undefined, tx);
    }
    // Section 6.5: the continue step, with the transaction_token (A-6). Never with the session credential and
    // never followed when deliver_to_session was set (it never is here).
    if (!tx.next.url) throw new AgentLoginError('continue URL withheld', 'protocol_error', undefined, tx);
    this.assertUnder(tx.next.url, metadata.transaction_endpoint);
    const c = await this.json(tx.next.url, { headers: { ...bearer, accept: 'application/json' } });
    if (c.status !== 200 || typeof (c.json as { redirect?: unknown }).redirect !== 'string') throw this.error('continue failed', c);
    const redirectUrl = (c.json as { redirect: string }).redirect;
    const rh = new URL(redirectUrl);
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
    const { issuer, metadata } = await this.discover();
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
      const res = await this.rpFetch(url);
      await res.arrayBuffer();
      const location = res.headers.get('location');
      if (!(res.status >= 300 && res.status < 400) || !location) {
        throw new AgentLoginError(`the application did not redirect to a sign-in (status ${res.status})`, 'no_authorization_request', res.status);
      }
      const next = new URL(location, url);
      if (next.origin === ae.origin && next.pathname === ae.pathname) {
        return this.signIn({ ...o, authorizationUrl: next.href, expectedHost: o.expectedHost ?? site });
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
      if (res.status >= 300 && res.status < 400 && location && i < maxRedirects) {
        const next = new URL(location, url);
        await res.arrayBuffer();
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
  private async rpFetch(u: URL, init: RequestInit = {}): Promise<Response> {
    if (u.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('non-https URL', 'insecure_url');
    const cookie = await this.cookies.header(u);
    const headers = new Headers(init.headers);
    if (!headers.has('accept')) headers.set('accept', 'text/html, application/json;q=0.9, */*;q=0.1');
    if (cookie) headers.set('cookie', cookie);
    headers.delete('authorization');
    let res: Response;
    try {
      res = await fetch(u, { ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000) });
    } catch (e) {
      throw new AgentLoginError(`request to ${u.host} failed: ${(e as Error).message}`, 'network_error');
    }
    await this.cookies.store(u, res.headers.getSetCookie());
    return res;
  }

  // ---- helpers ------------------------------------------------------------------------------------------
  /** A-3: the resource must come from this Agent's Issuer and point into its transaction endpoint; the client must be the one the agent set out to sign in to. */
  private check(tx: TransactionResource, issuer: string, m: IssuerMetadata, o: SignInOptions) {
    if (tx.iss !== issuer) throw new AgentLoginError(`transaction iss ${tx.iss} is not ${issuer}`, 'wrong_issuer', undefined, tx);
    this.assertUnder(tx.url, m.transaction_endpoint);
    if (tx.next?.url) this.assertUnder(tx.next.url, m.transaction_endpoint);
    if (!o.unsafeSkipHostCheck) {
      if (!o.expectedHost) throw new AgentLoginError('expectedHost is required: the host of the site you are signing in to', 'expected_host_required');
      const ok = [o.expectedHost, ...(o.acceptHosts ?? [])].map((h) => h.toLowerCase());
      if (!ok.includes(tx.client.redirect_host.toLowerCase())) throw new AgentLoginError(`this sign-in is for ${tx.client.redirect_host}, not ${o.expectedHost}`, 'unexpected_client', undefined, tx);
    }
  }
  private assertUnder(url: string, base: string) {
    if (!url.startsWith(base.endsWith('/') ? base : `${base}/`) && url !== base) throw new AgentLoginError(`URL ${new URL(url).origin}... is not under ${base}`, 'wrong_issuer');
    const u = new URL(url);
    if (u.protocol !== 'https:' && !this.opts.allowInsecure) throw new AgentLoginError('non-https URL from the Issuer', 'insecure_url');
  }
  /** One request to the Issuer: no cookies, no redirects, bounded in time and size. */
  private async json(url: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}): Promise<{ status: number; json: unknown; text: string; headers: Headers }> {
    const headers: Record<string, string> = { accept: 'application/json', ...init.headers };
    let body: string | undefined;
    if (init.body !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(init.body); }
    let res: Response;
    let text: string;
    try {
      res = await fetch(url, { method: init.method ?? 'GET', headers, body, redirect: 'manual', signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000) });
      const buf = await res.arrayBuffer();
      if (buf.byteLength > 64 * 1024) throw new Error('response larger than 64 KiB');
      text = Buffer.from(buf).toString('utf8');
    } catch (e) {
      throw new AgentLoginError(`request to the Issuer failed: ${(e as Error).message}`, 'network_error');
    }
    let json: unknown;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    return { status: res.status, json, text, headers: res.headers };
  }
  private error(what: string, r: { status: number; json: unknown; text: string }): AgentLoginError {
    const j = (r.json ?? {}) as { error?: string; error_description?: string; status?: string; reason?: string };
    return new AgentLoginError(`${what}: ${r.status} ${j.error ?? ''}${j.error_description ? ` (${j.error_description})` : ''}`.trim(), j.error ?? `http_${r.status}`, r.status, r.json);
  }
}
