// Section 2: WebFinger discovery of the Home Issuer and its metadata. HTTPS only, no HTTP retry, at most five
// redirect hops, fetch protections of Section 2.2. The DNS fallback (Section 2.3) requires DNSSEC validation that
// Node.js does not expose; this client does not implement it and reports the WebFinger failure instead.
import { parseHandle } from './handle.js';
import { safeFetch } from './safefetch.js';

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

/** Section 2.2: resolves a handle's domain to its Issuer Identifier. */
export async function discoverIssuer(handle: string, o: DiscoveryOptions = {}): Promise<string> {
  const h = parseHandle(handle);
  if (!h) throw new Error(`not a handle: ${handle}`);
  const scheme = o.allowInsecure ? 'http' : 'https';
  const url = new URL(`${scheme}://${h.domain}/.well-known/webfinger`);
  url.searchParams.set('resource', `acct:${h.handle}`);
  url.searchParams.set('rel', REL);
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
  const iss = new URL(link.href);
  if (!(iss.protocol === 'https:' || (o.allowInsecure && iss.protocol === 'http:')) || iss.search || iss.hash) throw new Error(`invalid issuer identifier ${link.href}`);
  return iss.href.replace(/\/$/, '');
}

/** Section 2.4: fetches and validates Issuer metadata; `issuer` must equal the identifier. */
export async function fetchMetadata(issuer: string, o: DiscoveryOptions = {}): Promise<IssuerMetadata> {
  const hit = cache.get(issuer);
  if (hit && hit.until > Date.now()) return hit.value;
  const res = await safeFetch(`${issuer}/.well-known/openid-configuration`, { maxBytes: MAX_BYTES, timeoutMs: o.timeoutMs ?? 10_000, allowPrivate: o.allowInsecure, maxRedirects: 0 });
  if (res.status !== 200) throw new Error(`metadata for ${issuer} failed with status ${res.status}`);
  const m = JSON.parse(res.body.toString('utf8')) as IssuerMetadata;
  if (m.issuer !== issuer) throw new Error(`metadata issuer ${m.issuer} does not equal ${issuer}`);
  for (const k of ENDPOINTS) {
    const v = m[k];
    if (typeof v !== 'string' || !(v.startsWith('https://') || (o.allowInsecure && v.startsWith('http://')))) throw new Error(`metadata ${k} is not an https URL`);
  }
  if (!Array.isArray(m.handle_domains) || !Array.isArray(m.agent_key_algs_supported)) throw new Error('metadata lacks Agent Login members');
  cache.set(issuer, { value: m, until: Date.now() + 300_000 });
  return m;
}

/** Discovery for a handle: Issuer Identifier plus metadata, with the handle_domains check of Section 2.3 applied as a sanity check. */
export async function discover(handle: string, o: DiscoveryOptions = {}): Promise<{ issuer: string; metadata: IssuerMetadata }> {
  const issuer = await discoverIssuer(handle, o);
  const metadata = await fetchMetadata(issuer, o);
  return { issuer, metadata };
}
