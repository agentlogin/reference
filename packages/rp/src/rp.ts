// The Relying Party side of Agent Login Core 1.0 (Sections 2.2 to 2.5, 5.1, 5.4 to 5.8 and 9).
// Conformance items R-1 to R-14 are referenced inline.
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { discoverIssuer, fetchMetadata, parseHandle, safeFetch, type IssuerMetadata } from 'agentlogin';
import { RelyingPartyError } from './errors.js';
import type { PendingSignIn } from './seal.js';

const T_SKEW = 60;
const T_CACHE_MS = 3_600_000; // discovery results are kept for an hour, well under T_CACHE
const MAX_BYTES = 64 * 1024;
const rnd = (n = 16) => randomBytes(n).toString('base64url');
const sameString = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

export interface IssuerConfig {
  /** Issuer Identifier. */
  issuer: string;
  /** This Issuer is a Relay (Section 8): tokens from it may carry `home_iss`. */
  relay?: boolean;
  /** Registered Client credentials at this Issuer; omit for an Open Client. */
  clientId?: string;
  clientSecret?: string;
}
export interface RelyingPartyOptions {
  /** Open Client: the HTTPS URL of your Client ID Metadata Document. Registered Client: the identifier the Issuer assigned (or set it per Issuer). */
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  /** Default `openid email profile`. Owner scopes need a Registered Client. */
  scopes?: string[];
  /** Issuers you accept. One Relay covers every Home Issuer the Relay accepts. */
  issuers: Array<string | IssuerConfig>;
  /** `allowlist` (default): only the Issuers above. `any`: any Issuer that a presented handle's domain designates; apply your own per-Issuer limits (Section 9 item 10). */
  federation?: 'allowlist' | 'any';
  /** At least 32 characters; encrypts the per-sign-in cookie. */
  stateSecret: string;
  /** Handle domain to Issuer Identifier, consulted before WebFinger. For development and private deployments. */
  staticIssuers?: Record<string, string>;
  /** ID Token algorithms accepted. Default `['ES256']`. */
  idTokenAlgs?: Array<'ES256' | 'EdDSA'>;
  /** Development only: http Issuers and loopback addresses. */
  allowInsecure?: boolean;
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
  /** Store this (the kit's handlers put it in an encrypted cookie) and pass it to `complete`. */
  pending: PendingSignIn;
}
export interface AgentIdentity {
  iss: string;
  sub: string;
  /** Account key: `iss` and `sub` joined by a space. Key your records on this, never on the handle (Section 9 item 1). */
  key: string;
  handle?: string;
  name?: string;
  preferredUsername?: string;
  ownerSub?: string;
  /** Per-owner limit key: `iss` and `owner_sub` joined by a space (Section 9 item 4). */
  ownerKey?: string;
  ownerName?: string;
  ownerEmail?: string;
  ownerVerifiedVia?: string;
  homeIss?: string;
  scopes: string[];
}
export interface SignIn {
  agent: AgentIdentity;
  claims: JWTPayload;
  issuer: string;
  /** Usable only at the Issuer's UserInfo Endpoint, until `accessTokenExpiresAt` (Section 9 item 5). Do not log it. */
  accessToken: string;
  accessTokenExpiresAt: number;
  returnTo?: string;
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

export class RelyingParty {
  private readonly issuers = new Map<string, IssuerConfig>();
  private readonly algs: string[];
  private readonly discoveryCache = new Map<string, { issuer: string; until: number }>();
  private readonly jwksCache = new Map<string, { jwks: JSONWebKeySet; fetchedAt: number }>();

  constructor(private readonly o: RelyingPartyOptions) {
    if (o.stateSecret.length < 32) throw new Error('stateSecret must be at least 32 characters');
    for (const i of o.issuers) {
      const c = typeof i === 'string' ? { issuer: i } : i;
      this.issuers.set(c.issuer, { ...c, issuer: c.issuer });
    }
    if (this.issuers.size === 0 && o.federation !== 'any') throw new Error('configure at least one Issuer, or federation: "any"');
    this.algs = o.idTokenAlgs ?? ['ES256'];
  }

  get options(): Readonly<RelyingPartyOptions> { return this.o; }
  /** True when `issuer` is one this Relying Party is configured to accept (Section 5.8). */
  isConfigured(issuer: string): boolean { return this.issuers.has(issuer); }
  private clientFor(issuer: string): { clientId: string; clientSecret?: string } {
    const c = this.issuers.get(issuer);
    return { clientId: c?.clientId ?? this.o.clientId, clientSecret: c?.clientSecret ?? this.o.clientSecret };
  }

  /** Section 2: the Issuer a handle's domain designates. Performed only for presented handles and cached (R-5, Section 9 item 9). */
  async resolve(handle: string): Promise<string> {
    const h = parseHandle(handle);
    if (!h) throw new RelyingPartyError('invalid_handle', 'not an Agent Handle');
    const pinned = this.o.staticIssuers?.[h.domain];
    if (pinned) return pinned;
    const hit = this.discoveryCache.get(h.domain);
    if (hit && hit.until > Date.now()) return hit.issuer;
    let issuer: string;
    try {
      issuer = await discoverIssuer(h.handle, { allowInsecure: this.o.allowInsecure, timeoutMs: this.o.timeoutMs });
      const m = await this.metadata(issuer); // verifies metadata `issuer` equals the discovered value (Section 2.2)
      void m;
    } catch (e) {
      throw new RelyingPartyError('discovery_failed', `could not find the Issuer for ${h.domain}: ${(e as Error).message}`);
    }
    if (this.discoveryCache.size > 5000) this.discoveryCache.clear();
    this.discoveryCache.set(h.domain, { issuer, until: Date.now() + T_CACHE_MS });
    return issuer;
  }
  private async metadata(issuer: string): Promise<IssuerMetadata> {
    try {
      return await fetchMetadata(issuer, { allowInsecure: this.o.allowInsecure, timeoutMs: this.o.timeoutMs });
    } catch (e) {
      throw new RelyingPartyError('discovery_failed', `Issuer metadata unavailable: ${(e as Error).message}`);
    }
  }

  /** Chooses the Issuer for a sign-in (Section 9 item 10). */
  private async choose(p: BeginOptions): Promise<string> {
    if (p.issuer) {
      const iss = p.issuer;
      if (!this.issuers.has(iss)) throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
      return iss;
    }
    if (p.handle) {
      const discovered = await this.resolve(p.handle);
      if (this.issuers.has(discovered)) return discovered;
      const relay = [...this.issuers.values()].find((i) => i.relay);
      if (relay) return relay.issuer;
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
    const issuer = await this.choose({ ...p, handle: loginHint });
    const m = await this.metadata(issuer);
    const { clientId } = this.clientFor(issuer);
    const pending: PendingSignIn = { state: rnd(), nonce: rnd(), verifier: rnd(32), issuer, loginHint, returnTo: p.returnTo };
    const u = new URL(m.authorization_endpoint);
    const q: Record<string, string> = {
      response_type: 'code',
      client_id: clientId,
      redirect_uri: this.o.redirectUri,
      scope: (p.scopes ?? this.o.scopes ?? ['openid', 'email', 'profile']).join(' '),
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
   * Section 5.8: third-party-initiated start. `iss` must be an Issuer this Relying Party accepts; nothing is fetched
   * from an unaccepted `iss`. Under `federation: "any"`, an `iss` that is not configured is accepted only when
   * discovery for `login_hint` yields exactly that Issuer.
   */
  async beginInitiated(p: { iss: string; loginHint?: string; returnTo?: string }): Promise<Begun> {
    const iss = p.iss;
    if (this.issuers.has(iss)) return this.begin({ issuer: iss, handle: p.loginHint, returnTo: p.returnTo });
    if (this.o.federation === 'any' && p.loginHint && (await this.resolve(p.loginHint)) === iss) return this.begin({ handle: p.loginHint, returnTo: p.returnTo });
    throw new RelyingPartyError('issuer_not_accepted', 'this application does not accept that Issuer');
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
    const error = one('error');
    if (error) throw new RelyingPartyError(error, `the Issuer answered ${error}`, one('error_description'));
    const code = one('code');
    if (!code) throw new RelyingPartyError('invalid_request', 'no code in the response');

    // Token Request, only to the recorded Issuer's Token Endpoint (Section 5.6).
    const m = await this.metadata(pending.issuer);
    const { clientId, clientSecret } = this.clientFor(pending.issuer);
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.o.redirectUri, code_verifier: pending.verifier });
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
    if (clientSecret) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')}`;
    else form.set('client_id', clientId);
    let tok: Record<string, unknown>;
    try {
      const r = await safeFetch(m.token_endpoint, { method: 'POST', headers, body: form.toString(), maxBytes: MAX_BYTES, timeoutMs: this.o.timeoutMs ?? 10_000, allowPrivate: this.o.allowInsecure });
      tok = JSON.parse(r.body.toString('utf8')) as Record<string, unknown>;
      if (r.status !== 200) throw new RelyingPartyError('token_request_failed', `the Issuer refused the code (${String(tok.error ?? r.status)})`);
    } catch (e) {
      if (e instanceof RelyingPartyError) throw e;
      throw new RelyingPartyError('token_request_failed', `token request failed: ${(e as Error).message}`);
    }
    if (typeof tok.id_token !== 'string' || typeof tok.access_token !== 'string' || String(tok.token_type).toLowerCase() !== 'bearer') throw new RelyingPartyError('token_request_failed', 'malformed token response');

    const claims = await this.validateIdToken(tok.id_token, { issuer: pending.issuer, nonce: pending.nonce, clientId, metadata: m });
    const expiresIn = typeof tok.expires_in === 'number' ? tok.expires_in : 600;
    return { agent: identity(claims), claims, issuer: pending.issuer, accessToken: tok.access_token, accessTokenExpiresAt: Math.floor(Date.now() / 1000) + expiresIn, returnTo: pending.returnTo };
  }

  /** Section 5.7 steps 2 to 7 (R-3, R-4, R-14). Nothing from a token that fails is returned. */
  async validateIdToken(idToken: string, x: { issuer: string; nonce: string; clientId: string; metadata?: IssuerMetadata }): Promise<JWTPayload> {
    const bad = (why: string) => new RelyingPartyError('invalid_id_token', `ID Token rejected: ${why}`);
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
      // Steps 3 and 4: `iss`, `aud`, `exp`.
      ({ payload } = await jwtVerify(idToken, createLocalJWKSet(jwks), { issuer: x.issuer, audience: x.clientId, algorithms: this.algs, clockTolerance: 0 }));
    } catch (e) {
      throw bad((e as Error).message);
    }
    if (typeof payload.aud !== 'string') throw bad('aud is not a single string');
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) throw bad('no sub');
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
      if (!ok) throw new RelyingPartyError('handle_binding_failed', 'home_iss is not among the Relay\'s home_issuers');
    }
    if (payload.email !== undefined) {
      if (typeof payload.email !== 'string' || payload.email_verified !== true) throw bad('email without email_verified true');
      const discovered = await this.resolve(payload.email);
      const expected = typeof homeIss === 'string' ? homeIss : x.issuer;
      if (discovered !== expected) throw new RelyingPartyError('handle_binding_failed', 'the handle\'s domain does not designate this Issuer');
    }
    return payload;
  }

  /** JWK Set of an Issuer; refetched once when `kid` is unknown, at most once a minute (R-13). */
  private async jwks(issuer: string, kid: string): Promise<JSONWebKeySet> {
    const cached = this.jwksCache.get(issuer);
    const has = (j: JSONWebKeySet) => j.keys.some((k) => k.kid === kid);
    if (cached && (has(cached.jwks) || Date.now() - cached.fetchedAt < 60_000)) return cached.jwks;
    const m = await this.metadata(issuer);
    try {
      const r = await safeFetch(m.jwks_uri, { maxBytes: MAX_BYTES, timeoutMs: this.o.timeoutMs ?? 10_000, allowPrivate: this.o.allowInsecure, maxRedirects: 0 });
      if (r.status !== 200) throw new Error(`status ${r.status}`);
      const jwks = JSON.parse(r.body.toString('utf8')) as JSONWebKeySet;
      if (!Array.isArray(jwks.keys)) throw new Error('not a JWK Set');
      this.jwksCache.set(issuer, { jwks, fetchedAt: Date.now() });
      return jwks;
    } catch (e) {
      throw new RelyingPartyError('discovery_failed', `JWK Set unavailable: ${(e as Error).message}`);
    }
  }

  /**
   * Section 9 items 5 and 6: the live check. Call it before actions with lasting effect, within the Access Token's
   * lifetime. Throws `revoked` when the Issuer answers 401 (key revoked, Agent or Account disabled).
   */
  async recheck(s: { issuer: string; accessToken: string; accessTokenExpiresAt?: number; agent: { sub: string } }): Promise<Record<string, unknown>> {
    if (s.accessTokenExpiresAt !== undefined && Math.floor(Date.now() / 1000) >= s.accessTokenExpiresAt) throw new RelyingPartyError('reauthentication_required', 'the Access Token expired; require a new sign-in');
    const m = await this.metadata(s.issuer);
    let r;
    try {
      r = await safeFetch(m.userinfo_endpoint, { headers: { authorization: `Bearer ${s.accessToken}` }, maxBytes: MAX_BYTES, timeoutMs: this.o.timeoutMs ?? 10_000, allowPrivate: this.o.allowInsecure, maxRedirects: 0 });
    } catch (e) {
      throw new RelyingPartyError('userinfo_failed', `UserInfo unavailable: ${(e as Error).message}`);
    }
    if (r.status === 401) throw new RelyingPartyError('revoked', 'the Issuer no longer vouches for this sign-in');
    if (r.status !== 200) throw new RelyingPartyError('userinfo_failed', `UserInfo answered ${r.status}`);
    const body = JSON.parse(r.body.toString('utf8')) as Record<string, unknown>;
    if (body.sub !== s.agent.sub) throw new RelyingPartyError('userinfo_failed', 'UserInfo sub does not match the ID Token');
    return body;
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

function identity(c: JWTPayload): AgentIdentity {
  const str = (k: string) => (typeof c[k] === 'string' ? (c[k] as string) : undefined);
  const iss = c.iss!;
  const sub = c.sub!;
  const ownerSub = str('owner_sub');
  return {
    iss,
    sub,
    key: `${iss} ${sub}`,
    handle: str('email'),
    name: str('name'),
    preferredUsername: str('preferred_username'),
    ownerSub,
    ownerKey: ownerSub ? `${iss} ${ownerSub}` : undefined,
    ownerName: str('owner_name'),
    ownerEmail: str('owner_email'),
    ownerVerifiedVia: str('owner_verified_via'),
    homeIss: str('home_iss'),
    scopes: typeof c.scope === 'string' ? c.scope.split(' ') : [],
  };
}
