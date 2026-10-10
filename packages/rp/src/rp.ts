// The Relying Party side of Agent Login Core 1.0 (Sections 2.2 to 2.5, 5.1, 5.4 to 5.8 and 9).
// Conformance items R-1 to R-14 are referenced inline. Node.js only: discovery and every request to an Issuer go
// through the address-filtering fetch of Section 2.2, which needs node:dns and node:http.
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { checkIssuerIdentifier, fetchMetadata, lookupIssuer, parseHandle, safeFetch, type IssuerMetadata } from 'agentlogin';
import { ISSUER_ERROR_CODES, RelyingPartyError, type RelyingPartyErrorCode } from './errors.js';
import type { PendingSignIn } from './seal.js';

const T_SKEW = 60;
const T_CACHE = 86_400; // seconds, Section 1.5
const MAX_BYTES = 64 * 1024;
const rnd = (n = 16) => randomBytes(n).toString('base64url');
const sameString = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export interface IssuerConfig {
  /** Issuer Identifier, exactly as the Issuer publishes it. */
  issuer: string;
  /** This Issuer is a Relay (Section 8): tokens from it may carry `home_iss`. At most one Relay may be configured. */
  relay?: boolean;
  /** Registered Client credentials at this Issuer; omit for an Open Client. */
  clientId?: string;
  clientSecret?: string;
  /** Scopes requested at this Issuer, when they differ from the default (owner scopes need a Registered Client). */
  scopes?: string[];
}
export interface RelyingPartyOptions {
  /** Open Client: the HTTPS URL of your Client ID Metadata Document. Registered Client: the identifier the Issuer assigned (or set it per Issuer). */
  clientId: string;
  /** Only with exactly one configured Issuer and without `federation: "any"`; otherwise set the secret on that Issuer's entry. A secret is never sent to an Issuer it was not configured for. */
  clientSecret?: string;
  redirectUri: string;
  /** Default `openid email profile`. */
  scopes?: string[];
  /** Issuers you accept. One Relay covers every Home Issuer that Relay accepts; do not also list a Home Issuer it relays. */
  issuers: Array<string | IssuerConfig>;
  /** `allowlist` (default): only the Issuers above. `any`: any Issuer that a presented handle designates; apply your own per-Issuer limits (Section 9 item 10). */
  federation?: 'allowlist' | 'any';
  /** At least 32 characters; encrypts the per-sign-in cookie. */
  stateSecret: string;
  /** Handle domain to Issuer Identifier, consulted before WebFinger. For development and private deployments. */
  staticIssuers?: Record<string, string>;
  /** ID Token algorithms accepted. Default `['ES256']`. */
  idTokenAlgs?: Array<'ES256' | 'EdDSA'>;
  /** Development only: http Issuers and loopback addresses. */
  allowInsecure?: boolean;
  /** Per-request limit for discovery, metadata, JWK Set, token and UserInfo requests. Default and maximum 10 000 ms (N_FETCH). */
  timeoutMs?: number;
}
export interface BeginOptions {
  /** The Agent Handle the user or agent presented. */
  handle?: string;
  /** Pick a configured Issuer explicitly. */
  issuer?: string;
  prompt?: 'consent' | 'none';
  scopes?: string[];
  returnTo?: string;
}
export interface Begun {
  /** The Authentication Request URL (Section 5.1). */
  url: string;
  /** Keep this for the callback (the kit's handlers put it in an encrypted cookie) and pass it to `complete`. */
  pending: PendingSignIn;
}
/** The Agent. Contains no personal data of the Owner. */
export interface AgentIdentity {
  iss: string;
  sub: string;
  /** Account key: `iss` and `sub` joined by a space. Key your records on this, never on the handle (Section 9 item 1). */
  key: string;
  handle?: string;
  name?: string;
  preferredUsername?: string;
  /** Per-owner limit key: `iss` and `owner_sub` joined by a space (Section 9 item 4). Opaque. */
  ownerKey?: string;
  homeIss?: string;
  scopes: string[];
}
/** The Owner's personal data, present when a Registered Client requested and was granted owner scopes. Store it apart from Agent data (Section 9 item 8). */
export interface OwnerIdentity {
  key: string;
  name?: string;
  email?: string;
  verifiedVia?: string;
}
export interface SignIn {
  agent: AgentIdentity;
  owner?: OwnerIdentity;
  /** The validated ID Token Claims. */
  claims: JWTPayload;
  issuer: string;
  /** A bearer credential, usable only at the Issuer's UserInfo Endpoint until `accessTokenExpiresAt` (Section 9 item 5). Do not log it; discard it when it expires. */
  accessToken: string;
  accessTokenExpiresAt: number;
  returnTo?: string;
}
/** What `recheck` needs; keep it in your session for as long as the Access Token lives. */
export interface LiveCheck {
  issuer: string;
  accessToken: string;
  accessTokenExpiresAt: number;
  sub: string;
}
export interface ClientMetadataInput {
  clientName?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  initiateLoginUri?: string;
  maxSignupsPerOwner?: number;
  requireReview?: boolean;
}
interface JwksEntry { jwks: JSONWebKeySet; until: number; lastMissRefetch: number }

export class RelyingParty {
  private readonly issuers = new Map<string, IssuerConfig>();
  private readonly relay?: IssuerConfig;
  private readonly algs: string[];
  private readonly timeoutMs: number;
  private readonly discoveryCache = new Map<string, { issuer: string; until: number }>();
  private readonly jwksCache = new Map<string, JwksEntry>();
  private relayChecked = false;

  constructor(private readonly o: RelyingPartyOptions) {
    if (typeof o.stateSecret !== 'string' || o.stateSecret.length < 32) throw new Error('stateSecret must be a string of at least 32 characters');
    if (typeof o.clientId !== 'string' || !o.clientId) throw new Error('clientId is required');
    if (!URL.canParse(o.redirectUri)) throw new Error('redirectUri must be an absolute URL');
    for (const i of o.issuers ?? []) {
      const c = typeof i === 'string' ? { issuer: i } : i;
      try {
        checkIssuerIdentifier(c.issuer, { allowInsecure: o.allowInsecure });
      } catch {
        throw new Error(`not an Issuer Identifier: ${c.issuer}`);
      }
      this.issuers.set(c.issuer, { ...c });
    }
    if (this.issuers.size === 0 && o.federation !== 'any') throw new Error('configure at least one Issuer, or federation: "any"');
    const relays = [...this.issuers.values()].filter((i) => i.relay);
    if (relays.length > 1) throw new Error('configure at most one Relay (Section 9 item 10)');
    this.relay = relays[0];
    if (this.relay && o.federation === 'any') throw new Error('a Relay cannot be combined with federation: "any": per-owner caps would be counted twice (Section 9 item 10)');
    if (o.clientSecret && (this.issuers.size !== 1 || o.federation === 'any')) {
      throw new Error('a top-level clientSecret is allowed only with exactly one Issuer and without federation: "any"; set clientSecret on the Issuer it belongs to');
    }
    this.algs = o.idTokenAlgs ?? ['ES256'];
    this.timeoutMs = Math.min(o.timeoutMs ?? 10_000, 10_000);
  }

  get options(): Readonly<RelyingPartyOptions> { return this.o; }
  /** True when `issuer` is one this Relying Party is configured to accept (Section 5.8). */
  isConfigured(issuer: string): boolean { return this.issuers.has(issuer); }
  /** Client identifier and, only for the Issuer it was configured for, the secret. */
  private clientFor(issuer: string): { clientId: string; clientSecret?: string } {
    const c = this.issuers.get(issuer);
    if (c?.clientId) return { clientId: c.clientId, clientSecret: c.clientSecret };
    return { clientId: this.o.clientId, clientSecret: c ? (c.clientSecret ?? this.o.clientSecret) : undefined };
  }

  /**
   * Section 2.2: the Issuer Identifier a handle designates. Performed only for presented handles and cached per the
   * response's freshness, at most T_CACHE (R-5, Section 9 item 9). The caller verifies the Issuer's metadata.
   */
  async resolve(handle: string): Promise<string> {
    const h = parseHandle(handle);
    if (!h) throw new RelyingPartyError('invalid_handle', 'not an Agent Handle');
    const pinned = this.o.staticIssuers?.[h.domain];
    if (pinned) return pinned;
    const hit = this.discoveryCache.get(h.handle);
    if (hit && hit.until > Date.now()) return hit.issuer;
    let found;
    try {
      found = await lookupIssuer(h.handle, { allowInsecure: this.o.allowInsecure, timeoutMs: this.timeoutMs });
    } catch (e) {
      throw new RelyingPartyError('discovery_failed', `could not find the Issuer for ${h.domain}`, undefined, { cause: e });
    }
    const ttl = Math.min(found.maxAge ?? 300, T_CACHE);
    if (ttl > 0) {
      if (this.discoveryCache.size >= 5000) this.discoveryCache.delete(this.discoveryCache.keys().next().value!);
      this.discoveryCache.set(h.handle, { issuer: found.issuer, until: Date.now() + ttl * 1000 });
    }
    return found.issuer;
  }
  /** Section 2.4 metadata; `issuer` in it must equal the identifier (Section 2.2). */
  private async metadata(issuer: string): Promise<IssuerMetadata> {
    try {
      return await fetchMetadata(issuer, { allowInsecure: this.o.allowInsecure, timeoutMs: this.timeoutMs });
    } catch (e) {
      const configured = this.issuers.has(issuer);
      throw new RelyingPartyError(configured && /does not equal|invalid issuer/.test((e as Error).message) ? 'configuration_error' : 'discovery_failed', configured ? 'metadata of a configured Issuer is unavailable or does not match its identifier' : 'Issuer metadata unavailable', undefined, { cause: e });
    }
  }
  /** Section 9 item 10: a Relay and a Home Issuer it relays must not both be configured. Checked once, lazily. */
  private async checkRelayConfiguration(): Promise<void> {
    if (this.relayChecked || !this.relay) return;
    const accepted = (await this.metadata(this.relay.issuer)).home_issuers;
    const all = Array.isArray(accepted) && accepted.length === 1 && accepted[0] === '*';
    const others = [...this.issuers.keys()].filter((i) => i !== this.relay!.issuer);
    const overlap = others.filter((i) => all || (Array.isArray(accepted) && accepted.includes(i)));
    if (overlap.length) {
      throw new RelyingPartyError('configuration_error', 'a Relay is configured together with a Home Issuer it relays; per-owner caps would be counted twice (Section 9 item 10)');
    }
    this.relayChecked = true;
  }

  /** Chooses the Issuer for a sign-in (Section 9 item 10). Nothing is fetched from an Issuer that is not accepted. */
  private async choose(p: BeginOptions): Promise<string> {
    if (p.issuer) {
      if (!this.issuers.has(p.issuer)) throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
      return p.issuer;
    }
    if (p.handle) {
      const discovered = await this.resolve(p.handle);
      if (this.issuers.has(discovered)) return discovered;
      if (this.relay) return this.relay.issuer;
      if (this.o.federation === 'any') return discovered;
      throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept agents from that provider');
    }
    if (this.issuers.size === 1) return [...this.issuers.keys()][0]!;
    throw new RelyingPartyError('handle_required', 'an Agent Handle is needed to choose the Issuer');
  }

  /** Section 5.1: build the Authentication Request (R-1) and record the Issuer for this `state` (R-2). */
  async begin(p: BeginOptions = {}): Promise<Begun> {
    let loginHint: string | undefined;
    if (p.handle !== undefined) {
      const h = parseHandle(p.handle);
      if (!h) throw new RelyingPartyError('invalid_handle', 'not an Agent Handle');
      loginHint = h.handle;
    }
    await this.checkRelayConfiguration();
    const issuer = await this.choose({ ...p, handle: loginHint });
    const m = await this.metadata(issuer);
    const { clientId } = this.clientFor(issuer);
    const pending: PendingSignIn = { state: rnd(), nonce: rnd(), verifier: rnd(32), issuer, loginHint, returnTo: p.returnTo };
    const u = new URL(m.authorization_endpoint);
    const q: Record<string, string> = {
      response_type: 'code',
      client_id: clientId,
      redirect_uri: this.o.redirectUri,
      scope: (p.scopes ?? this.issuers.get(issuer)?.scopes ?? this.o.scopes ?? ['openid', 'email', 'profile']).join(' '),
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: createHash('sha256').update(pending.verifier, 'ascii').digest('base64url'),
      code_challenge_method: 'S256',
    };
    if (loginHint) q.login_hint = loginHint; // Section 9: sent whenever the expected handle is known (R-13)
    if (p.prompt) q.prompt = p.prompt;
    for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
    return { url: u.href, pending };
  }

  /**
   * Section 5.8: third-party-initiated start. `iss` must be an Issuer this Relying Party accepts; no request is sent
   * to any other `iss`. Under `federation: "any"`, an `iss` that is not configured is accepted only when discovery
   * for `login_hint` yields exactly that Issuer. Every other case is `issuer_not_accepted`.
   */
  async beginInitiated(p: { iss: string; loginHint?: string; returnTo?: string }): Promise<Begun> {
    const refuse = () => new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
    if (this.issuers.has(p.iss)) return this.begin({ issuer: p.iss, handle: p.loginHint && parseHandle(p.loginHint) ? p.loginHint : undefined, returnTo: p.returnTo });
    if (this.o.federation !== 'any' || !p.loginHint) throw refuse();
    let discovered: string | undefined;
    try {
      discovered = await this.resolve(p.loginHint);
    } catch {
      discovered = undefined;
    }
    if (discovered !== p.iss) throw refuse();
    return this.begin({ handle: p.loginHint, returnTo: p.returnTo });
  }

  /** Sections 5.4 to 5.7: validate the redirect, exchange the code, validate the ID Token. */
  async complete(p: { params: URLSearchParams; pending: PendingSignIn | null }): Promise<SignIn> {
    const { params, pending } = p;
    const one = (k: string) => {
      const all = params.getAll(k);
      if (all.length > 1) throw new RelyingPartyError('invalid_request', `repeated parameter ${k}`);
      return all[0];
    };
    // Step 1 (R-2): `state` bound to this session, `iss` equal to the Issuer recorded for it.
    const state = one('state');
    if (!pending || !state || !sameString(state, pending.state)) throw new RelyingPartyError('invalid_state', 'this sign-in was not started in this session, or it expired');
    const iss = one('iss');
    if (!iss || iss !== pending.issuer) throw new RelyingPartyError('issuer_mismatch', 'the response did not come from the Issuer the request was sent to');
    if (!this.issuers.has(pending.issuer) && this.o.federation !== 'any') throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
    const error = one('error');
    if (error) {
      const known = (ISSUER_ERROR_CODES as readonly string[]).includes(error);
      throw new RelyingPartyError(known ? (error as RelyingPartyErrorCode) : 'issuer_error', known ? `the Issuer answered ${error}` : 'the Issuer answered with an error', one('error_description')?.slice(0, 500));
    }
    const code = one('code');
    if (!code) throw new RelyingPartyError('invalid_request', 'no code in the response');

    // Token Request, only to the recorded Issuer's Token Endpoint (Section 5.6).
    const m = await this.metadata(pending.issuer);
    const { clientId, clientSecret } = this.clientFor(pending.issuer);
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.o.redirectUri, code_verifier: pending.verifier });
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
    if (clientSecret) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')}`;
    else form.set('client_id', clientId);
    let status: number;
    let tok: unknown;
    try {
      const r = await safeFetch(m.token_endpoint, { method: 'POST', headers, body: form.toString(), maxBytes: MAX_BYTES, timeoutMs: this.timeoutMs, allowPrivate: this.o.allowInsecure });
      status = r.status;
      tok = JSON.parse(r.body.toString('utf8'));
    } catch (e) {
      throw new RelyingPartyError('token_request_failed', 'the token request failed', undefined, { cause: e });
    }
    if (status !== 200 || !isObject(tok)) {
      const why = isObject(tok) && typeof tok.error === 'string' && /^[a-z_]{1,40}$/.test(tok.error) ? tok.error : `status ${status}`;
      throw new RelyingPartyError('token_request_failed', `the Issuer refused the code (${why})`);
    }
    if (typeof tok.id_token !== 'string' || typeof tok.access_token !== 'string' || String(tok.token_type).toLowerCase() !== 'bearer') throw new RelyingPartyError('token_request_failed', 'malformed token response');

    const claims = await this.validateIdToken(tok.id_token, { issuer: pending.issuer, nonce: pending.nonce, clientId, metadata: m });
    const expiresIn = typeof tok.expires_in === 'number' && tok.expires_in > 0 ? Math.min(tok.expires_in, 3600) : 600;
    return { ...identity(claims), claims, issuer: pending.issuer, accessToken: tok.access_token, accessTokenExpiresAt: Math.floor(Date.now() / 1000) + expiresIn, returnTo: pending.returnTo };
  }

  /** Section 5.7 steps 2 to 7 (R-3, R-4, R-14). Nothing from a token that fails is returned. */
  async validateIdToken(idToken: string, x: { issuer: string; nonce: string; clientId: string; metadata?: IssuerMetadata }): Promise<JWTPayload> {
    const bad = (why: string, cause?: unknown) => new RelyingPartyError('invalid_id_token', `ID Token rejected: ${why}`, undefined, { cause });
    let header;
    try {
      header = decodeProtectedHeader(idToken);
    } catch {
      throw bad('malformed');
    }
    if (typeof header.alg !== 'string' || !this.algs.includes(header.alg)) throw bad('algorithm not accepted');
    if (typeof header.kid !== 'string') throw bad('no kid');
    const jwks = await this.jwks(x.issuer, header.kid);
    let payload: JWTPayload;
    try {
      // Step 2: signature, with `alg` pinned and matched to the key (and to the JWK's `alg` when present).
      // Steps 3 and 4: `iss`, `aud`, `exp` (required), with no tolerance on `exp`.
      ({ payload } = await jwtVerify(idToken, createLocalJWKSet(jwks), { issuer: x.issuer, audience: x.clientId, algorithms: this.algs, clockTolerance: 0, requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'] }));
    } catch (e) {
      throw bad('signature or standard claims', e);
    }
    if (typeof payload.aud !== 'string') throw bad('aud is not a single string');
    if (typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.sub.length > 255) throw bad('sub');
    if (typeof payload.exp !== 'number') throw bad('exp');
    if (typeof payload.iat !== 'number' || payload.iat > Math.floor(Date.now() / 1000) + T_SKEW) throw bad('iat is in the future');
    if (typeof payload.nonce !== 'string' || !sameString(payload.nonce, x.nonce)) throw bad('nonce'); // step 5
    if (payload.actor_type !== 'agent') throw bad('actor_type is not agent'); // step 6

    // Step 7, Section 2.5: the handle-to-Issuer binding.
    const homeIss = payload.home_iss;
    if (homeIss !== undefined) {
      const cfg = this.issuers.get(x.issuer);
      if (typeof homeIss !== 'string' || !cfg?.relay) throw new RelyingPartyError('handle_binding_failed', 'home_iss from an Issuer that is not configured as a Relay');
      const accepted = (x.metadata ?? (await this.metadata(x.issuer))).home_issuers;
      const ok = Array.isArray(accepted) && ((accepted.length === 1 && accepted[0] === '*') || accepted.includes(homeIss));
      if (!ok) throw new RelyingPartyError('handle_binding_failed', "home_iss is not among the Relay's home_issuers");
    }
    if (payload.email !== undefined) {
      if (typeof payload.email !== 'string' || payload.email_verified !== true) throw bad('email without email_verified true');
      const expected = typeof homeIss === 'string' ? homeIss : x.issuer;
      const discovered = await this.resolve(payload.email);
      if (discovered !== expected) throw new RelyingPartyError('handle_binding_failed', "the handle's domain does not designate this Issuer");
      if (expected !== x.issuer) await this.metadata(expected); // Section 2.2: the designated Issuer's metadata names itself
    }
    return payload;
  }

  /**
   * JWK Set of an Issuer (Section 5.7 step 2). Cached per the response's freshness (five minutes when it states none,
   * a day at most); refetched once when `kid` is unknown, at most once a minute (R-13).
   */
  private async jwks(issuer: string, kid: string): Promise<JSONWebKeySet> {
    const now = Date.now();
    const cached = this.jwksCache.get(issuer);
    const has = (j: JSONWebKeySet) => j.keys.some((k) => k.kid === kid);
    if (cached && now < cached.until && has(cached.jwks)) return cached.jwks;
    if (cached && now < cached.until && now - cached.lastMissRefetch < 60_000) return cached.jwks; // unknown kid, refetched recently
    const m = await this.metadata(issuer);
    let jwks: JSONWebKeySet;
    let maxAge = 300;
    try {
      const r = await safeFetch(m.jwks_uri, { maxBytes: MAX_BYTES, timeoutMs: this.timeoutMs, allowPrivate: this.o.allowInsecure, maxRedirects: 0 });
      if (r.status !== 200) throw new Error(`status ${r.status}`);
      const parsed: unknown = JSON.parse(r.body.toString('utf8'));
      if (!isObject(parsed) || !Array.isArray(parsed.keys) || !parsed.keys.every(isObject)) throw new Error('not a JWK Set');
      jwks = parsed as unknown as JSONWebKeySet;
      const cc = /(?:^|,)\s*max-age=(\d+)/i.exec(String(r.headers['cache-control'] ?? ''));
      if (cc) maxAge = Math.min(Number(cc[1]), T_CACHE);
    } catch (e) {
      throw new RelyingPartyError('discovery_failed', 'JWK Set unavailable', undefined, { cause: e });
    }
    if (this.jwksCache.size >= 200 && !cached) this.jwksCache.delete(this.jwksCache.keys().next().value!);
    this.jwksCache.set(issuer, { jwks, until: now + Math.max(maxAge, 60) * 1000, lastMissRefetch: cached && now < cached.until ? now : (cached?.lastMissRefetch ?? 0) });
    return jwks;
  }

  /**
   * Section 9 items 5 and 6: the live check. Call it before actions with lasting effect. Throws `revoked` when the
   * Issuer answers 401 (key revoked, Agent or Account disabled) and `reauthentication_required` once the Access Token
   * has expired: require a new sign-in then.
   */
  async recheck(s: LiveCheck | SignIn): Promise<Record<string, unknown>> {
    const sub = 'sub' in s ? s.sub : s.agent.sub;
    if (Math.floor(Date.now() / 1000) >= s.accessTokenExpiresAt) throw new RelyingPartyError('reauthentication_required', 'the Access Token expired; require a new sign-in');
    if (!this.issuers.has(s.issuer) && this.o.federation !== 'any') throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
    const m = await this.metadata(s.issuer);
    let status: number;
    let body: unknown;
    try {
      const r = await safeFetch(m.userinfo_endpoint, { headers: { authorization: `Bearer ${s.accessToken}` }, maxBytes: MAX_BYTES, timeoutMs: this.timeoutMs, allowPrivate: this.o.allowInsecure, maxRedirects: 0 });
      status = r.status;
      body = status === 200 ? JSON.parse(r.body.toString('utf8')) : undefined;
    } catch (e) {
      throw new RelyingPartyError('userinfo_failed', 'UserInfo unavailable', undefined, { cause: e });
    }
    if (status === 401) throw new RelyingPartyError('revoked', 'the Issuer no longer vouches for this sign-in');
    if (status !== 200 || !isObject(body)) throw new RelyingPartyError('userinfo_failed', `UserInfo answered ${status}`);
    if (body.sub !== sub) throw new RelyingPartyError('userinfo_failed', 'UserInfo sub does not match the ID Token');
    return body;
  }
  /** The part of a sign-in that `recheck` needs; discard it when `accessTokenExpiresAt` has passed. */
  liveCheckOf(s: SignIn): LiveCheck {
    return { issuer: s.issuer, accessToken: s.accessToken, accessTokenExpiresAt: s.accessTokenExpiresAt, sub: s.agent.sub };
  }

  /** Section 4.2: the Client ID Metadata Document an Open Client serves at its `client_id` URL (R-10). */
  clientMetadata(x: ClientMetadataInput = {}): Record<string, unknown> {
    const doc: Record<string, unknown> = { client_id: this.o.clientId, redirect_uris: [this.o.redirectUri], token_endpoint_auth_method: 'none' };
    if (x.clientName) doc.client_name = x.clientName;
    if (x.logoUri) doc.logo_uri = x.logoUri;
    if (x.tosUri) doc.tos_uri = x.tosUri;
    if (x.policyUri) doc.policy_uri = x.policyUri;
    if (x.initiateLoginUri) doc.initiate_login_uri = x.initiateLoginUri;
    if (x.maxSignupsPerOwner !== undefined) doc.max_signups_per_owner = x.maxSignupsPerOwner;
    if (x.requireReview !== undefined) doc.require_review = x.requireReview;
    return doc;
  }
}

function identity(c: JWTPayload): { agent: AgentIdentity; owner?: OwnerIdentity } {
  const str = (k: string) => (typeof c[k] === 'string' ? (c[k] as string) : undefined);
  const iss = c.iss!;
  const sub = c.sub!;
  const ownerSub = str('owner_sub');
  const ownerKey = ownerSub ? `${iss} ${ownerSub}` : undefined;
  const agent: AgentIdentity = { iss, sub, key: `${iss} ${sub}`, handle: str('email'), name: str('name'), preferredUsername: str('preferred_username'), ownerKey, homeIss: str('home_iss'), scopes: typeof c.scope === 'string' ? c.scope.split(' ') : [] };
  const hasOwnerData = str('owner_name') !== undefined || str('owner_email') !== undefined;
  const owner: OwnerIdentity | undefined = ownerKey && hasOwnerData ? { key: ownerKey, name: str('owner_name'), email: c.owner_email_verified === true ? str('owner_email') : undefined, verifiedVia: str('owner_verified_via') } : undefined;
  return { agent, owner };
}
