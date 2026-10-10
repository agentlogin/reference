// Section 7: Agent Keys, enrollment, revocation, Accounts and management operations.
import { calculateJwkThumbprint, compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { ENROLLMENT_TYP } from './constants.js';
import type { IssuerContext } from './context.js';
import { OAuthError } from './errors.js';
import type { Agent, AgentKey, Credential, P256Jwk, Transaction } from './store.js';
import { TERMINAL } from './store.js';
import { isPlainObject, parseBearer, randomSecret, sha256, typMatches } from './util.js';

const B64U_32 = /^[A-Za-z0-9_-]{43}$/; // 32 octets
/** The P-256 field prime; a coordinate encoding is canonical only when its value is below it. */
const P256_PRIME = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const coordinateValue = (b64u: string): bigint => BigInt(`0x${Buffer.from(b64u, 'base64url').toString('hex')}`);
/**
 * 43 base64url characters carry 258 bits, so the last character has two unused bits and every 32-octet value has four
 * spellings. Only the one a conforming encoder produces is accepted; the key identifier (a thumbprint over these
 * strings) then names the decoded point, which is what Section 7.2 compares.
 */
const canonicalB64u = (s: string): boolean => Buffer.from(s, 'base64url').toString('base64url') === s;

/** Section 7.2: strict public-key validation. */
export async function validateP256Jwk(jwk: unknown): Promise<P256Jwk> {
  const bad = (d: string) => new OAuthError(400, 'invalid_request', `jwk: ${d}`);
  if (!isPlainObject(jwk)) throw bad('object required');
  const keys = Object.keys(jwk).sort();
  if (keys.join(',') !== 'crv,kty,x,y') throw bad('exactly kty, crv, x, y are permitted');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw bad('only EC P-256 is supported');
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !B64U_32.test(jwk.x) || !B64U_32.test(jwk.y)) throw bad('coordinates must be 32 octets base64url');
  if (Buffer.from(jwk.x, 'base64url').length !== 32 || Buffer.from(jwk.y, 'base64url').length !== 32) throw bad('coordinates must decode to exactly 32 octets');
  if (!canonicalB64u(jwk.x) || !canonicalB64u(jwk.y)) throw bad('coordinates must be canonical base64url');
  if (coordinateValue(jwk.x) >= P256_PRIME || coordinateValue(jwk.y) >= P256_PRIME) throw bad('coordinates must be less than the field prime');
  try {
    // Web Cryptography rejects points that are not on the curve.
    await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  } catch {
    throw bad('point is not on the curve');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

/** Section 7.2: a `pending` key not proved within T_ASSERT is deleted. Applied wherever a key is read, so it is never seen again. */
async function dropIfUnproved(ctx: IssuerContext, key: AgentKey | undefined): Promise<AgentKey | undefined> {
  if (key && key.status === 'pending' && (!key.challenge || ctx.now() > key.challenge.expiresAt)) {
    await ctx.store.deleteKey(key.kid);
    return undefined;
  }
  return key;
}
export const getLiveKey = async (ctx: IssuerContext, kid: string): Promise<AgentKey | undefined> => dropIfUnproved(ctx, await ctx.store.getKey(kid));
export async function listLiveKeys(ctx: IssuerContext, handle: string): Promise<AgentKey[]> {
  const keys: AgentKey[] = [];
  for (const k of await ctx.store.listKeys(handle)) {
    const live = await dropIfUnproved(ctx, k);
    if (live) keys.push(live);
  }
  return keys;
}
/** Section 7.1: a key whose `expires_at` has passed is not `active`. */
const isActive = (ctx: IssuerContext, k: AgentKey): boolean => k.status === 'active' && ctx.now() < k.expiresAt;

export function keyRecord(ctx: IssuerContext, k: AgentKey): Record<string, unknown> {
  const status = k.status === 'active' && ctx.now() >= k.expiresAt ? 'expired' : k.status;
  return { kid: k.kid, status, jwk: k.jwk, permissions: k.permissions, name: k.name, created_at: k.createdAt, expires_at: k.expiresAt };
}

/** Section 7.2: create a pending key. */
export async function enrollKey(ctx: IssuerContext, handle: string, body: unknown): Promise<{ record: Record<string, unknown>; challenge: string; proof_url: string }> {
  if (!isPlainObject(body)) throw new OAuthError(400, 'invalid_request', 'body must be an object');
  const jwk = await validateP256Jwk(body.jwk);
  // The thumbprint is taken over canonical coordinates, so equal identifiers mean equal decoded points (Section 7.2).
  const kid = await calculateJwkThumbprint(jwk, 'sha256');
  if (await ctx.store.wasRevoked(handle, kid)) throw new OAuthError(400, 'invalid_request', 'this public key was revoked for this handle');
  const existing = await getLiveKey(ctx, kid);
  if (existing && existing.handle !== handle) throw new OAuthError(400, 'invalid_request', 'public key is enrolled for another handle');
  if (existing && (existing.status === 'pending' || isActive(ctx, existing))) throw new OAuthError(400, 'invalid_request', 'key already enrolled');
  const now = ctx.now();
  let expiresAt = now + ctx.constants.T_KEY;
  if (body.expires_at !== undefined) {
    if (typeof body.expires_at !== 'number' || !Number.isInteger(body.expires_at) || body.expires_at <= now) throw new OAuthError(400, 'invalid_request', 'expires_at');
    expiresAt = Math.min(body.expires_at, now + ctx.constants.T_KEY_MAX);
  }
  const challenge = randomSecret();
  const key: AgentKey = {
    kid,
    handle,
    status: 'pending',
    jwk,
    permissions: { share_owner: false },
    name: typeof body.name === 'string' ? body.name.slice(0, 200) : undefined,
    createdAt: now,
    expiresAt,
    challenge: { value: challenge, expiresAt: now + ctx.constants.T_ASSERT },
  };
  await ctx.store.putKey(key);
  return { record: keyRecord(ctx, key), challenge, proof_url: `${ctx.issuer}/agents/${encodeURIComponent(handle)}/keys/${encodeURIComponent(kid)}/proof` };
}

/** Section 7.2: verify the enrollment proof and activate the key. */
export async function proveKey(ctx: IssuerContext, handle: string, kid: string, body: unknown): Promise<Record<string, unknown>> {
  const key = await getLiveKey(ctx, kid);
  const now = ctx.now();
  // Section 6.7: `unknown_key` (401) when `kid` names no enrolled key of the handle; a pending key that timed out is gone (Section 7.2).
  if (!key || key.handle !== handle) throw new OAuthError(401, 'unknown_key');
  // Section 7.4 table: proofs with a revoked or expired key are refused with `key_revoked`.
  if (key.status === 'revoked' || key.status === 'expired' || (key.status === 'active' && now >= key.expiresAt)) throw new OAuthError(401, 'key_revoked');
  if (!isPlainObject(body) || typeof body.proof !== 'string') throw new OAuthError(400, 'invalid_request', 'proof required');
  // An active key has no unconsumed challenge left, so no proof can satisfy the `nonce` rule of Section 7.2.
  if (key.status !== 'pending' || !key.challenge) throw new OAuthError(400, 'invalid_assertion', 'the key has no unconsumed challenge');
  const jws = body.proof;
  const bad = (d: string) => new OAuthError(400, 'invalid_assertion', d);
  if (Buffer.byteLength(jws) > ctx.constants.N_ASSERTION) throw bad('proof too large');
  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    throw bad('malformed JWS');
  }
  if (header.alg !== 'ES256') throw bad('alg');
  if (!typMatches(header.typ, ENROLLMENT_TYP)) throw bad('typ');
  if (header.kid !== kid) throw bad('kid');
  for (const f of ['jwk', 'jku', 'x5u', 'x5c', 'crit'] as const) if (header[f] !== undefined) throw bad(`header ${f} not permitted`);
  let payload: Record<string, unknown>;
  try {
    const r = await compactVerify(jws, await importJWK(key.jwk, 'ES256'), { algorithms: ['ES256'] });
    payload = JSON.parse(Buffer.from(r.payload).toString('utf8'));
    if (!isPlainObject(payload)) throw new Error();
  } catch {
    throw new OAuthError(401, 'invalid_signature');
  }
  if (payload.iss !== handle || payload.sub !== handle) throw bad('iss and sub must be the handle');
  if (payload.aud !== ctx.issuer) throw bad('aud');
  if (payload.nonce !== key.challenge.value) throw bad('nonce');
  const { iat, exp } = payload;
  if (typeof iat !== 'number' || typeof exp !== 'number') throw bad('iat and exp required');
  if (exp > iat + ctx.constants.T_ASSERT || now >= exp || iat < now - ctx.constants.T_ASSERT || iat > now + ctx.constants.T_SKEW) throw bad('iat/exp window');
  if (typeof payload.jti !== 'string') throw bad('jti required');
  key.status = 'active';
  key.challenge = undefined;
  await ctx.store.putKey(key);
  return keyRecord(ctx, key);
}

/** Section 7.3 and the table of Section 7.4: effects of revoking a key. */
export async function revokeKeyEffects(ctx: IssuerContext, key: AgentKey): Promise<void> {
  key.status = 'revoked';
  key.revokedAt = ctx.now();
  key.challenge = undefined;
  await ctx.store.putKey(key);
  await ctx.store.rememberRevoked(key.handle, key.kid);
  for (const tx of await ctx.store.listOpenTransactions({ kid: key.kid })) await deny(ctx, tx, 'key_revoked');
  await voidCodes(ctx, { kid: key.kid });
  await revokeTokens(ctx, { kid: key.kid });
}

/** Section 7.3: revoke every pending and active key of a handle; with an Owner Credential also every Delegated Credential for it. */
export async function revokeAllKeys(ctx: IssuerContext, handle: string, cred: Credential): Promise<void> {
  for (const k of await listLiveKeys(ctx, handle)) if (k.status === 'active' || k.status === 'pending') await revokeKeyEffects(ctx, k);
  if (cred.kind === 'owner') for (const d of await ctx.store.listCredentials({ handle, kind: 'delegated' })) await ctx.store.deleteCredential(d.hash);
}

/** Section 7.4: effects of disabling an Account. */
export async function setAccountStatus(ctx: IssuerContext, handle: string, clientId: string, status: 'enabled' | 'disabled'): Promise<Record<string, unknown>> {
  const account = await ctx.store.getAccount(handle, clientId);
  if (!account) throw new OAuthError(404, 'not_found', 'no account for this client');
  account.status = status;
  await ctx.store.putAccount(account);
  if (status === 'disabled') {
    for (const tx of await ctx.store.listOpenTransactions({ handle, clientId })) {
      if (tx.assertedAt) await deny(ctx, tx, 'access_denied'); // only transactions past step 7
    }
    await voidCodes(ctx, { handle, clientId });
    await revokeTokens(ctx, { handle, clientId });
  }
  return accountRecord(account);
}

/** Section 7.4 table, "Agent disabled": open transactions it asserted are denied, codes voided, tokens invalidated. */
export async function setAgentEnabled(ctx: IssuerContext, agent: Agent, enabled: boolean): Promise<void> {
  agent.enabled = enabled;
  await ctx.store.putAgent(agent);
  if (!enabled) {
    for (const tx of await ctx.store.listOpenTransactions({ handle: agent.handle })) await deny(ctx, tx, 'access_denied');
    await voidCodes(ctx, { handle: agent.handle });
    await revokeTokens(ctx, { handle: agent.handle });
  }
}

/**
 * Section 7.4 table, "Agent deleted": as disabled, then keys, Consent Records, Accounts and Delegated Credentials are
 * deleted; the per-owner count of Section 7.6 is retained. An Agent created later with the same handle starts with none.
 */
export async function deleteAgent(ctx: IssuerContext, agent: Agent): Promise<void> {
  await setAgentEnabled(ctx, agent, false);
  for (const k of await ctx.store.listKeys(agent.handle)) {
    if (k.status === 'active' || k.status === 'pending') await revokeKeyEffects(ctx, k);
    await ctx.store.deleteKey(k.kid);
  }
  for (const c of await ctx.store.listConsents(agent.handle)) await ctx.store.deleteConsent(c.handle, c.clientId);
  for (const a of await ctx.store.listAccounts(agent.handle)) await ctx.store.deleteAccount(a.handle, a.clientId);
  for (const d of await ctx.store.listCredentials({ handle: agent.handle, kind: 'delegated' })) await ctx.store.deleteCredential(d.hash);
  await ctx.store.deleteAgent(agent.handle);
}

/**
 * Sections 6.6 and 7.8: only an Owner Credential from a session that authenticated the Owner by `passkey`, `oidc`,
 * `domain`, or `email` plus a factor the Agent cannot read approves a transaction or grants `share_owner`. An allow-list:
 * a credential whose session is not recorded, or was established by a one-time code or link alone, does not qualify.
 */
export const approvalSession = (cred: Credential): boolean =>
  cred.kind === 'owner' && (cred.sessionAuth === 'passkey' || cred.sessionAuth === 'oidc' || cred.sessionAuth === 'domain' || cred.sessionAuth === 'email_factor');

async function deny(ctx: IssuerContext, tx: Transaction, reason: 'key_revoked' | 'access_denied'): Promise<void> {
  tx.status = 'denied';
  tx.reason = reason;
  tx.terminalAt = ctx.now();
  tx.challenge = undefined;
  tx.continueSecret ??= randomSecret();
  await ctx.store.putTransaction(tx);
}
async function voidCodes(ctx: IssuerContext, f: { kid?: string; handle?: string; clientId?: string }): Promise<void> {
  for (const c of await ctx.store.listCodes(f)) {
    if (!c.used && !c.voided) {
      c.voided = true;
      await ctx.store.putCode(c);
    }
  }
}
async function revokeTokens(ctx: IssuerContext, f: { kid?: string; handle?: string; clientId?: string }): Promise<void> {
  for (const t of await ctx.store.listAccessTokens(f)) {
    if (!t.revoked) {
      t.revoked = true;
      await ctx.store.putAccessToken(t);
    }
  }
}

export function accountRecord(a: { clientId: string; status: string; firstSignedInAt: number; lastSignedInAt: number; signInCount: number }): Record<string, unknown> {
  return { client_id: a.clientId, status: a.status, first_signed_in_at: a.firstSignedInAt, last_signed_in_at: a.lastSignedInAt, sign_in_count: a.signInCount };
}

/** Section 7.8: resolves the credential and checks that the handle belongs to its Owner. */
export async function authorizeManagement(ctx: IssuerContext, authorization: string | undefined, handle: string, delegable: boolean): Promise<Credential> {
  const bearer = parseBearer(authorization);
  const cred = bearer ? await ctx.store.getCredential(sha256(bearer)) : undefined;
  if (!cred) throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  const agent = await ctx.store.getAgent(handle);
  if (!agent || agent.ownerId !== cred.ownerId || (cred.kind === 'delegated' && cred.handle !== handle)) throw new OAuthError(404, 'not_found');
  if (cred.kind === 'delegated' && !delegable) throw new OAuthError(403, 'insufficient_permission', undefined, { 'WWW-Authenticate': 'Bearer error="insufficient_scope"' });
  return cred;
}

export const openTransactions = (txs: Transaction[]) => txs.filter((t) => !TERMINAL.has(t.status));
