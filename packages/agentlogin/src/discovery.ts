// Section 2: WebFinger discovery of the Home Issuer and its metadata. HTTPS only, no HTTP retry, at most five
// redirect hops, fetch protections of Section 2.2. The DNS fallback (Section 2.3) requires DNSSEC validation that
// Node.js does not expose; this client does not implement it and reports the WebFinger failure instead.
import { acctUri, parseHandle } from './handle.js';
import { freshness, safeFetch } from './safefetch.js';
export { freshness };

export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  transaction_endpoint: string;
  agents_endpoint: string;
  handle_domains: string[];
  agent_key_algs_supported: string[];
  agent_login_versions_supported: string[];
  /** Present for a Relay (Section 2.4). */
  home_issuers?: string[];
  id_token_signing_alg_values_supported?: string[];
  [k: string]: unknown;
}
export interface DiscoveryOptions {
  /** Development only: permit http issuers and private addresses. */
  allowInsecure?: boolean;
  timeoutMs?: number;
}
const REL = 'http://openid.net/specs/connect/1.0/issuer';
const MAX_BYTES = 64 * 1024;
const ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'transaction_endpoint', 'agents_endpoint'] as const;

const cache = new Map<string, { value: IssuerMetadata; until: number }>();

type Headers = Record<string, string | string[] | undefined>;
/** Freshness of a result reached through redirects: the shortest of all hops. A redirect that states nothing is not reused. */
export function chainFreshness(res: { headers: Headers; redirects: Array<{ headers: Headers }> }, fallback: number): number {
  return Math.min(freshness(res.headers, fallback), ...res.redirects.map((r) => freshness(r.headers, 0)));
}

/** The WebFinger request for a handle (Section 2.2): the acct URI, itself percent-encoded, as the `resource` value. */
export function webfingerUrl(handle: string, o: DiscoveryOptions = {}): URL {
  const h = parseHandle(handle);
  if (!h) throw new Error(`not a handle: ${handle}`);
  const url = new URL(`${o.allowInsecure ? 'http' : 'https'}://${h.domain}/.well-known/webfinger`);
  url.searchParams.set('resource', acctUri(h.handle));
  url.searchParams.set('rel', REL);
  return url;
}

/** Section 2.2: resolves a handle to its Issuer Identifier. */
export async function discoverIssuer(handle: string, o: DiscoveryOptions = {}): Promise<string> {
  return (await lookupIssuer(handle, o)).issuer;
}

/** As discoverIssuer, with the freshness lifetime the WebFinger response allows (seconds; undefined when it states none). */
export async function lookupIssuer(handle: string, o: DiscoveryOptions = {}): Promise<{ issuer: string; maxAge: number }> {
  const h = parseHandle(handle);
  if (!h) throw new Error(`not a handle: ${handle}`);
  const url = webfingerUrl(h.handle, o);
  const res = await safeFetch(url, { maxBytes: MAX_BYTES, timeoutMs: o.timeoutMs ?? 10_000, allowPrivate: o.allowInsecure, maxRedirects: 5, accept: 'application/jrd+json, application/json' });
  if (res.status !== 200) throw new Error(`WebFinger lookup for ${h.domain} failed with status ${res.status}`);
  let jrd: { links?: Array<{ rel?: string; href?: string }> };
  try {
    jrd = JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new Error('WebFinger response is not JSON');
  }
  const link = (jrd.links ?? []).find((l) => l.rel === REL);
  if (!link?.href) throw new Error(`no issuer link for ${h.handle}`);
  // The lifetime the whole exchange allows, delegating redirects included: a domain that withdraws or re-points its
  // delegation must not stay bound to the old Issuer for as long as the old target said.
  return { issuer: checkIssuerIdentifier(link.href, o), maxAge: chainFreshness(res, 300) };
}

/** An Issuer Identifier is an https URL without query or fragment; it is compared as a string, never normalised. */
export function checkIssuerIdentifier(issuer: string, o: DiscoveryOptions = {}): string {
  let u: URL;
  try {
    u = new URL(issuer);
  } catch {
    throw new Error(`invalid issuer identifier ${issuer}`);
  }
  if (!(u.protocol === 'https:' || (o.allowInsecure && u.protocol === 'http:')) || u.search || u.hash || issuer.includes('?') || issuer.includes('#') || u.username || u.password) {
    throw new Error(`invalid issuer identifier ${issuer}`);
  }
  return issuer;
}

/**
 * Section 2.4: fetches and validates Issuer metadata; `issuer` must equal the identifier. Cached for as long as the
 * response allows (five minutes when it states nothing, never for no-store), separately per security mode.
 */
export async function fetchMetadata(issuer: string, o: DiscoveryOptions = {}): Promise<IssuerMetadata> {
  checkIssuerIdentifier(issuer, o);
  const key = `${o.allowInsecure ? 'insecure' : 'secure'}|${issuer}`; // what development mode accepted is never served to a strict caller
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.value;
  // Section 4 of OpenID Connect Discovery: a terminating "/" is removed before the well-known path is appended.
  const res = await safeFetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, { maxBytes: MAX_BYTES, timeoutMs: o.timeoutMs ?? 10_000, allowPrivate: o.allowInsecure, maxRedirects: 0 });
  if (res.status !== 200) throw new Error(`metadata for ${issuer} failed with status ${res.status}`);
  const m = JSON.parse(res.body.toString('utf8')) as IssuerMetadata;
  if (typeof m !== 'object' || m === null || m.issuer !== issuer) throw new Error(`metadata issuer ${String(m?.issuer)} does not equal ${issuer}`);
  for (const k of ENDPOINTS) {
    const v = m[k];
    if (typeof v !== 'string' || !URL.canParse(v) || !(v.startsWith('https://') || (o.allowInsecure && v.startsWith('http://')))) throw new Error(`metadata ${k} is not an https URL`);
  }
  if (!Array.isArray(m.handle_domains) || !Array.isArray(m.agent_key_algs_supported)) throw new Error('metadata lacks Agent Login members');
  cache.delete(key);
  const ttl = freshness(res.headers, 300);
  if (ttl > 0) {
    if (cache.size >= 200) cache.delete(cache.keys().next().value!); // bounded: identifiers can be chosen by whoever presents a handle
    cache.set(key, { value: m, until: Date.now() + ttl * 1000 });
  }
  return m;
}

/** Discovery for a handle: Issuer Identifier plus metadata, with the handle_domains check of Section 2.3 applied as a sanity check. */
export async function discover(handle: string, o: DiscoveryOptions = {}): Promise<{ issuer: string; metadata: IssuerMetadata }> {
  const issuer = await discoverIssuer(handle, o);
  const metadata = await fetchMetadata(issuer, o);
  return { issuer, metadata };
}
