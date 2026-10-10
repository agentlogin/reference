// Section 7: Agent Keys, enrollment, revocation, Accounts and management operations.
import { calculateJwkThumbprint, compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { ENROLLMENT_TYP } from './constants.js';
import type { IssuerContext } from './context.js';
import { OAuthError } from './errors.js';
import type { AgentKey, Credential, P256Jwk, Transaction } from './store.js';
import { TERMINAL } from './store.js';
import { isPlainObject, parseBearer, randomSecret, sha256, typMatches } from './util.js';

const B64U_32 = /^[A-Za-z0-9_-]{43}$/; // 32 octets

/** Section 7.2: strict public-key validation. */
export async function validateP256Jwk(jwk: unknown): Promise<P256Jwk> {
  const bad = (d: string) => new OAuthError(400, 'invalid_request', `jwk: ${d}`);
  if (!isPlainObject(jwk)) throw bad('object required');
  const keys = Object.keys(jwk).sort();
  if (keys.join(',') !== 'crv,kty,x,y') throw bad('exactly kty, crv, x, y are permitted');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw bad('only EC P-256 is supported');
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !B64U_32.test(jwk.x) || !B64U_32.test(jwk.y)) throw bad('coordinates must be 32 octets base64url');
  try {
    // Web Cryptography rejects points that are not on the curve.
    await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  } catch {
    throw bad('point is not on the curve');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

export function keyRecord(ctx: IssuerContext, k: AgentKey): Record<string, unknown> {
  const status = k.status === 'active' && ctx.now() >= k.expiresAt ? 'expired' : k.status;
  return { kid: k.kid, status, jwk: k.jwk, permissions: k.permissions, name: k.name, created_at: k.createdAt, expires_at: k.expiresAt };
}

/** Section 7.2: create a pending key. */
export async function enrollKey(ctx: IssuerContext, handle: string, body: unknown): Promise<{ record: Record<string, unknown>; challenge: string; proof_url: string }> {
  if (!isPlainObject(body)) throw new OAuthError(400, 'invalid_request', 'body must be an object');
  const jwk = await validateP256Jwk(body.jwk);
  const kid = await calculateJwkThumbprint(jwk, 'sha256');
  if (await ctx.store.wasRevoked(handle, kid)) throw new OAuthError(400, 'invalid_request', 'this public key was revoked for this handle');
  const existing = await ctx.store.getKey(kid);
  if (existing && existing.handle !== handle) throw new OAuthError(400, 'invalid_request', 'public key is enrolled for another handle');
  if (existing && existing.status === 'pending' && existing.challenge && ctx.now() > existing.challenge.expiresAt) existing.status = 'expired'; // Section 7.2: unproved after T_ASSERT
  if (existing && (existing.status === 'active' || existing.status === 'pending')) throw new OAuthError(409, 'invalid_request', 'key already enrolled');
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
  const key = await ctx.store.getKey(kid);
  const now = ctx.now();
  if (!key || key.handle !== handle) throw new OAuthError(404, 'unknown_key');
  if (key.status === 'pending' && key.challenge && now > key.challenge.expiresAt) {
    await ctx.store.putKey({ ...key, status: 'expired', challenge: undefined });
    throw new OAuthError(404, 'unknown_key', 'pending key expired');
  }
  if (key.status !== 'pending' || !key.challenge) throw new OAuthError(409, 'invalid_request', 'key is not pending');
  if (!isPlainObject(body) || typeof body.proof !== 'string') throw new OAuthError(400, 'invalid_request', 'proof required');
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
  for (const k of await ctx.store.listKeys(handle)) if (k.status === 'active' || k.status === 'pending') await revokeKeyEffects(ctx, k);
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
