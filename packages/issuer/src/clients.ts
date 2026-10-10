// Section 4: Open Clients (Client ID Metadata Documents) and Registered Clients.
import { safeFetch } from './safefetch.js';
import type { Client, Store } from './store.js';
import type { Constants } from './constants.js';
import { OAuthError } from './errors.js';
import { isPlainObject, nowSeconds, randomSecret, sha256, randomId } from './util.js';
import { isIP } from 'node:net';

export interface ClientContext {
  store: Store;
  constants: Constants;
  /** Development only: accept http and loopback redirect URIs and document URLs. */
  allowInsecureClients: boolean;
}

/** Section 4.2 / CIMD Section 3: syntactic validation of an Open Client identifier; no fetch. */
export function parseClientIdUrl(clientId: string, allowInsecure = false): URL | null {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.href !== clientId) return null; // must be in normalised form
  if (!(url.protocol === 'https:' || (allowInsecure && url.protocol === 'http:'))) return null;
  if (url.username || url.password || url.hash || url.href.endsWith('#')) return null;
  if (!url.pathname || url.pathname === '/') return null;
  if (!allowInsecure && isIP(url.hostname.replace(/^\[|\]$/g, ''))) return null; // host must be a domain name
  if (url.pathname.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  return url;
}

function isLoopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '');
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || /^127\./.test(h);
}

/** Section 4.2: a redirect URI acceptable for an Open Client. */
export function validOpenRedirectUri(uri: string, allowInsecure: boolean): boolean {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.protocol === 'https:') return allowInsecure || !isLoopback(u.hostname);
    return allowInsecure && u.protocol === 'http:';
  } catch {
    return false;
  }
}

const optString = (v: unknown): string | undefined => (typeof v === 'string' && v.length <= 2048 ? v : undefined);
const httpsUri = (v: unknown): string | undefined => {
  const s = optString(v);
  if (!s) return undefined;
  try {
    return new URL(s).protocol === 'https:' ? s : undefined;
  } catch {
    return undefined;
  }
};

/** Validates document or registration metadata common to both tiers. Throws OAuthError on failure. */
function readCommonMetadata(doc: Record<string, unknown>, allowInsecure: boolean): Pick<Client, 'redirectUris' | 'clientName' | 'logoUri' | 'tosUri' | 'policyUri' | 'initiateLoginUri' | 'maxSignupsPerOwner' | 'requireReview'> {
  const uris = doc.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === 'string')) {
    throw new OAuthError(400, 'invalid_client_metadata', 'redirect_uris required');
  }
  for (const u of uris as string[]) {
    if (!validOpenRedirectUri(u, allowInsecure)) throw new OAuthError(400, 'invalid_client_metadata', `redirect_uri not permitted: ${u}`);
  }
  let max: number | undefined;
  if (doc.max_signups_per_owner !== undefined) {
    const m = doc.max_signups_per_owner;
    if (typeof m !== 'number' || !Number.isInteger(m) || m < 0 || m > 1_000_000) throw new OAuthError(400, 'invalid_client_metadata', 'max_signups_per_owner');
    max = m;
  }
  if (doc.require_review !== undefined && typeof doc.require_review !== 'boolean') throw new OAuthError(400, 'invalid_client_metadata', 'require_review');
  if (doc.id_token_signed_response_alg !== undefined && doc.id_token_signed_response_alg !== 'ES256') throw new OAuthError(400, 'invalid_client_metadata', 'id_token_signed_response_alg must be ES256');
  return {
    redirectUris: uris as string[],
    clientName: optString(doc.client_name),
    logoUri: httpsUri(doc.logo_uri),
    tosUri: httpsUri(doc.tos_uri),
    policyUri: httpsUri(doc.policy_uri),
    initiateLoginUri: httpsUri(doc.initiate_login_uri),
    maxSignupsPerOwner: max,
    requireReview: doc.require_review === true,
  };
}

/** Section 4.2: fetch and validate a Client ID Metadata Document. */
export async function fetchOpenClient(ctx: ClientContext, url: URL): Promise<Client> {
  let res;
  try {
    res = await safeFetch(url, { maxBytes: ctx.constants.N_CIMD, timeoutMs: ctx.constants.N_FETCH_MS, allowPrivate: ctx.allowInsecureClients, maxRedirects: 0 });
  } catch (e) {
    throw new OAuthError(400, 'invalid_request', `client metadata unavailable: ${(e as Error).message}`);
  }
  if (res.status !== 200) throw new OAuthError(400, 'invalid_request', `client metadata status ${res.status}`);
  const ct = String(res.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
  if (!(ct === 'application/json' || ct.endsWith('+json'))) throw new OAuthError(400, 'invalid_request', 'client metadata is not JSON');
  let doc: unknown;
  try {
    doc = JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new OAuthError(400, 'invalid_request', 'client metadata is not valid JSON');
  }
  if (!isPlainObject(doc)) throw new OAuthError(400, 'invalid_request', 'client metadata is not an object');
  if (doc.client_id !== url.href) throw new OAuthError(400, 'invalid_request', 'client_id mismatch in metadata');
  if (doc.token_endpoint_auth_method !== 'none') throw new OAuthError(400, 'invalid_request', 'token_endpoint_auth_method must be none');
  const common = readCommonMetadata(doc, ctx.allowInsecureClients);
  const now = nowSeconds();
  const cc = String(res.headers['cache-control'] ?? '');
  const m = /max-age=(\d+)/.exec(cc);
  const ttl = m ? Math.min(Number(m[1]), ctx.constants.T_CACHE) : 300;
  const client: Client = { clientId: url.href, type: 'open', tokenEndpointAuthMethod: 'none', ...common, fetchedAt: now, cacheUntil: now + ttl };
  await ctx.store.putClient(client);
  return client;
}

/** Resolves a `client_id` to a client (Section 5.2 step 1). */
export async function resolveClient(ctx: ClientContext, clientId: string): Promise<Client> {
  const existing = await ctx.store.getClient(clientId);
  if (existing && existing.type === 'registered') return existing;
  if (existing && existing.type === 'open' && (existing.cacheUntil ?? 0) > nowSeconds()) return existing;
  const url = parseClientIdUrl(clientId, ctx.allowInsecureClients);
  if (!url) throw new OAuthError(400, 'invalid_request', 'unknown client_id');
  return fetchOpenClient(ctx, url);
}

/** Section 5.2 step 2: simple string comparison, except that a Registered Client's loopback IP literal URI may vary its port (RFC 8252 Section 7.3). */
export function redirectUriMatches(client: Client, uri: string): boolean {
  if (client.redirectUris.includes(uri)) return true;
  if (client.type !== 'registered') return false;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol !== 'http:' || !(u.hostname === '127.0.0.1' || u.hostname === '[::1]')) return false;
  return client.redirectUris.some((r) => {
    try {
      const reg = new URL(r);
      return reg.protocol === 'http:' && reg.hostname === u.hostname && reg.pathname === u.pathname && reg.search === u.search;
    } catch {
      return false;
    }
  });
}

/** Section 4.3: Dynamic Client Registration (RFC 7591) for Registered Clients. Returns the response body. */
export async function registerClient(ctx: ClientContext, body: unknown): Promise<Record<string, unknown>> {
  if (!isPlainObject(body)) throw new OAuthError(400, 'invalid_client_metadata', 'body must be an object');
  const common = readCommonMetadata(body, true /* loopback permitted for Registered Clients, RFC 8252 */);
  for (const u of common.redirectUris) {
    const p = new URL(u).protocol;
    if (p !== 'https:' && !(p === 'http:' && isLoopback(new URL(u).hostname)) && !ctx.allowInsecureClients) {
      throw new OAuthError(400, 'invalid_client_metadata', `redirect_uri not permitted: ${u}`);
    }
  }
  if (body.grant_types !== undefined && !(Array.isArray(body.grant_types) && body.grant_types.every((g) => g === 'authorization_code'))) throw new OAuthError(400, 'invalid_client_metadata', 'grant_types');
  if (body.response_types !== undefined && !(Array.isArray(body.response_types) && body.response_types.every((r) => r === 'code'))) throw new OAuthError(400, 'invalid_client_metadata', 'response_types');
  const method = body.token_endpoint_auth_method ?? 'client_secret_basic';
  if (method !== 'client_secret_basic' && method !== 'client_secret_post') throw new OAuthError(400, 'invalid_client_metadata', 'token_endpoint_auth_method');
  const clientId = randomId();
  const secret = randomSecret();
  const client: Client = { clientId, type: 'registered', tokenEndpointAuthMethod: method, clientSecretHash: sha256(secret), ...common };
  await ctx.store.putClient(client);
  return {
    client_id: clientId,
    client_secret: secret,
    client_id_issued_at: nowSeconds(),
    client_secret_expires_at: 0,
    token_endpoint_auth_method: method,
    redirect_uris: client.redirectUris,
    client_name: client.clientName,
    logo_uri: client.logoUri,
    tos_uri: client.tosUri,
    policy_uri: client.policyUri,
    initiate_login_uri: client.initiateLoginUri,
    max_signups_per_owner: client.maxSignupsPerOwner,
    require_review: client.requireReview,
  };
}
