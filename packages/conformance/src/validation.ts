// Independent checks of the wire representation. Do not reuse the issuer's validators: a shared bug would pass.
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

function expect(condition: unknown, detail: string): asserts condition {
  if (!condition) throw new Error(detail);
}

function strings(meta: Record<string, unknown>, name: string): string[] {
  const value = meta[name];
  expect(Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0), `${name} must be an array of nonempty strings`);
  return value as string[];
}

/** Section 2.4, including the member types inherited from OpenID Discovery / RFC 8414. */
export function validateMetadata(meta: Record<string, unknown>, issuer: string, registrationRequired: boolean): void {
  expect(meta.issuer === issuer, 'issuer mismatch');
  const configured = new URL(issuer);
  // The documented local-development command explicitly targets HTTP loopback. This exception is confined to
  // that origin; it never permits a remote HTTP endpoint or weakens a production HTTPS issuer's metadata checks.
  const local = configured.protocol === 'http:' && (configured.hostname === 'localhost' || configured.hostname === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(configured.hostname));
  const url = (value: unknown, name: string, identifier = false) => {
    expect(typeof value === 'string' && URL.canParse(value), `${name} must be an absolute HTTPS URL`);
    const u = new URL(value);
    expect((u.protocol === 'https:' || (local && u.origin === configured.origin)) && !u.username && !u.password && !u.hash && (!identifier || !u.search), `${name} must be an absolute HTTPS URL without userinfo or fragment${identifier ? ' or query' : ''}`);
  };
  url(issuer, 'issuer', true);
  for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'transaction_endpoint', 'agents_endpoint']) url(meta[key], key);
  if (registrationRequired || meta.registration_endpoint !== undefined) url(meta.registration_endpoint, 'registration_endpoint');
  for (const [key, required] of [
    ['response_types_supported', ['code']],
    ['code_challenge_methods_supported', ['S256']],
    ['id_token_signing_alg_values_supported', ['ES256']],
    ['agent_key_algs_supported', ['ES256']],
    ['scopes_supported', ['openid', 'email', 'profile', 'owner_profile', 'owner_email']],
    ['token_endpoint_auth_methods_supported', ['none', 'client_secret_basic']],
    ['agent_login_versions_supported', ['1.0']],
  ] as const) {
    const offered = strings(meta, key);
    for (const value of required) expect(offered.includes(value), `${key} must contain ${value}`);
  }
  for (const [key, required] of [['response_modes_supported', 'query'], ['subject_types_supported', 'public'], ['grant_types_supported', 'authorization_code']] as const) {
    const offered = strings(meta, key);
    expect(offered.length === 1 && offered[0] === required, `${key} must be ["${required}"]`);
  }
  for (const key of ['client_id_metadata_document_supported', 'authorization_response_iss_parameter_supported']) expect(meta[key] === true, `${key} must be true`);
  for (const key of ['request_parameter_supported', 'request_uri_parameter_supported']) expect(meta[key] === false, `${key} must be false`);
  const methods = meta.token_endpoint_auth_methods_supported as string[];
  if (methods.includes('private_key_jwt') || meta.token_endpoint_auth_signing_alg_values_supported !== undefined) {
    const algorithms = strings(meta, 'token_endpoint_auth_signing_alg_values_supported');
    if (methods.includes('private_key_jwt')) expect(algorithms.includes('ES256'), 'private_key_jwt requires token_endpoint_auth_signing_alg_values_supported to contain ES256');
  }
  for (const domain of strings(meta, 'handle_domains')) {
    const bare = domain.startsWith('*.') ? domain.slice(2) : domain;
    expect(bare.length <= 253 && !isIP(bare) && domainToASCII(bare) === bare && bare.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)), 'handle_domains must contain lower-case A-label domains, optionally prefixed by *.');
  }
  if (meta.home_issuers !== undefined) {
    const homes = strings(meta, 'home_issuers');
    if (homes.includes('*')) expect(homes.length === 1, 'home_issuers wildcard must be ["*"]');
    else for (const home of homes) url(home, 'home_issuers member', true);
    url(meta.op_policy_uri, 'op_policy_uri');
  } else if (meta.op_policy_uri !== undefined) url(meta.op_policy_uri, 'op_policy_uri');
}

/** Section 2.4's explicit prohibitions, kept separate for checklist I-2. */
export function validateForbiddenMetadata(meta: Record<string, unknown>): void {
  expect(meta.end_session_endpoint === undefined, 'end_session_endpoint present');
  const grants = strings(meta, 'grant_types_supported');
  expect(grants.length === 1 && grants[0] === 'authorization_code', 'grant_types_supported must be ["authorization_code"]');
  expect(!strings(meta, 'code_challenge_methods_supported').includes('plain'), 'plain PKCE advertised');
  for (const key of ['id_token_signing_alg_values_supported', 'agent_key_algs_supported', 'token_endpoint_auth_signing_alg_values_supported']) {
    if (meta[key] !== undefined) expect(!strings(meta, key).includes('none'), `${key} advertises none`);
  }
  expect(!strings(meta, 'id_token_signing_alg_values_supported').includes('RS256'), 'RS256 ID Token signing advertised');
}

/** OAuth query responses retain the registered URI's query component, including repeated application parameters. */
export function redirectMatches(target: URL, registered: string): boolean {
  const expected = new URL(registered);
  if (target.origin !== expected.origin || target.pathname !== expected.pathname || target.username !== expected.username || target.password !== expected.password || target.hash !== expected.hash) return false;
  const remaining = [...target.searchParams];
  for (const [key, value] of expected.searchParams) {
    const index = remaining.findIndex(([k, v]) => k === key && v === value);
    if (index < 0) return false;
    remaining.splice(index, 1);
  }
  return true;
}

/** Sections 5.4, 5.5 and 5.7: response members are single-valued; application query members are preserved. */
export function authorizationRedirectMatches(target: URL, registered: string, state: string | undefined, issuer: string, response: 'code' | 'error'): boolean {
  if (!redirectMatches(target, registered)) return false;
  const params = target.searchParams;
  for (const name of ['code', 'state', 'iss', 'error', 'error_description', 'error_uri']) {
    if (params.getAll(name).length > 1) return false;
  }
  return !!state && !!issuer && params.get('state') === state && params.get('iss') === issuer &&
    !!params.get(response) && !params.has(response === 'code' ? 'error' : 'code');
}

/** Sections 6.2 and 6.7: consuming a continue URL does not change the retained terminal outcome. */
export function singleUseContinueError(body: unknown, status: 'completed' | 'denied' | 'expired', transactionEndpoint?: string): boolean {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  const fields = body as Record<string, unknown>;
  if (fields.error !== 'transaction_expired' || fields.status !== status || !fields.next || typeof fields.next !== 'object' || Array.isArray(fields.next)) return false;
  const next = fields.next as Record<string, unknown>;
  if (status === 'completed') return next.action === 'none' && next.method === undefined && next.url === undefined;
  if (next.action !== 'continue' || next.method !== 'GET' || typeof next.url !== 'string' || !URL.canParse(next.url) || !transactionEndpoint) return false;
  const url = new URL(next.url);
  const endpoint = new URL(transactionEndpoint);
  const local = endpoint.protocol === 'http:' && (endpoint.hostname === 'localhost' || endpoint.hostname === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(endpoint.hostname));
  // The current continue URL may rotate; do not impose URL stability or a path layout on the issuer.
  return url.origin === endpoint.origin && (url.protocol === 'https:' || local) && !url.username && !url.password && !url.hash;
}

/** Section 5.6 requires at most one success: replay detection may invalidate even the first request before delivery. */
export function concurrentAccessTokens(responses: Array<{ status: number; json: unknown }>): string[] {
  expect(responses.length > 1, 'the concurrent redemption probe requires multiple responses');
  const successful = responses.filter((response) => response.status === 200);
  expect(successful.length <= 1, `concurrent redemptions answered ${responses.map((response) => response.status).join(', ')}: at most one may succeed`);
  const tokens: string[] = [];
  for (const response of responses) {
    const body = response.json;
    expect(body !== null && typeof body === 'object' && !Array.isArray(body), 'redemption must return a JSON object');
    const fields = body as Record<string, unknown>;
    if (response.status === 200) {
      expect(typeof fields.access_token === 'string' && fields.access_token.length > 0 && typeof fields.id_token === 'string' && fields.id_token.length > 0, 'a successful redemption must return access_token and id_token');
      tokens.push(fields.access_token);
    } else expect(response.status === 400 && fields.error === 'invalid_grant' && fields.access_token === undefined && fields.id_token === undefined, 'unsuccessful redemptions must answer 400 invalid_grant without tokens');
  }
  return tokens;
}
