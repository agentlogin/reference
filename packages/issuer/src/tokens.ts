// Section 5.6 (Token Endpoint), Section 3 (ID Token, UserInfo).
import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import type { IssuerContext } from './context.js';
import { OAuthError, invalidToken } from './errors.js';
import type { Agent, Client, Owner } from './store.js';
import { nowSeconds, randomSecret, safeEqual, sha256 } from './util.js';
import type { Scope } from './constants.js';

export interface TokenRequest {
  grantType?: string;
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  clientIdParam?: string;
  clientSecretParam?: string;
  basic?: { id: string; secret: string };
}

/** Section 4.3: client authentication at the Token Endpoint. Returns the authenticated or presented client. */
export async function authenticateClient(ctx: IssuerContext, r: TokenRequest): Promise<Client> {
  const presentedId = r.basic?.id ?? r.clientIdParam;
  if (!presentedId) throw new OAuthError(401, 'invalid_client', 'client identification required', { 'WWW-Authenticate': 'Basic realm="token"' });
  const client = await ctx.store.getClient(presentedId);
  if (!client) throw new OAuthError(401, 'invalid_client');
  if (client.type === 'open') {
    if (r.basic || r.clientSecretParam) throw new OAuthError(401, 'invalid_client', 'open clients do not authenticate');
    return client;
  }
  const secret = client.tokenEndpointAuthMethod === 'client_secret_basic' ? r.basic?.secret : r.clientSecretParam;
  if (!secret || !client.clientSecretHash || !safeEqual(sha256(secret), client.clientSecretHash)) {
    throw new OAuthError(401, 'invalid_client', undefined, { 'WWW-Authenticate': 'Basic realm="token"' });
  }
  return client;
}

/** Section 5.6: exchange a code. */
export async function exchangeCode(ctx: IssuerContext, client: Client, r: TokenRequest): Promise<Record<string, unknown>> {
  if (r.grantType !== 'authorization_code') throw new OAuthError(400, 'unsupported_grant_type');
  if (!r.code || !r.redirectUri || !r.codeVerifier) throw new OAuthError(400, 'invalid_grant', 'code, redirect_uri and code_verifier are required');
  const code = await ctx.store.getCode(sha256(r.code));
  const fail = () => new OAuthError(400, 'invalid_grant');
  if (!code) throw fail();
  if (code.used) {
    // Section 5.4: revoke tokens already issued for a code presented twice.
    for (const t of await ctx.store.listAccessTokens({ handle: code.handle, clientId: code.clientId })) {
      if (t.txnId === code.txnId) {
        t.revoked = true;
        await ctx.store.putAccessToken(t);
      }
    }
    throw fail();
  }
  if (code.voided || ctx.now() >= code.expiresAt || code.clientId !== client.clientId || code.redirectUri !== r.redirectUri) throw fail();
  const challenge = createHash('sha256').update(r.codeVerifier, 'ascii').digest('base64url');
  if (!safeEqual(challenge, code.codeChallenge)) throw fail();
  const key = await ctx.store.getKey(code.kid);
  if (!key || key.status !== 'active' || ctx.now() >= key.expiresAt) throw fail();
  const account = await ctx.store.getAccount(code.handle, code.clientId);
  if (account?.status === 'disabled') throw fail();
  const agent = await ctx.store.getAgent(code.handle);
  const owner = agent && (await ctx.store.getOwner(agent.ownerId));
  if (!agent || !agent.enabled || !owner) throw fail();
  code.used = true;
  await ctx.store.putCode(code);

  const accessToken = randomSecret();
  const now = ctx.now();
  await ctx.store.putAccessToken({
    hash: sha256(accessToken),
    txnId: code.txnId,
    clientId: client.clientId,
    handle: code.handle,
    kid: code.kid,
    scopes: code.scopes,
    expiresAt: now + ctx.constants.T_TOKEN,
    revoked: false,
  });
  const idToken = await mintIdToken(ctx, { agent, owner, client, scopes: code.scopes, nonce: code.nonce, authTime: code.authTime });
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ctx.constants.T_TOKEN,
    id_token: idToken,
    scope: code.scopes.join(' '),
  };
}

/** Section 3.1 Claims for the granted scopes. */
export function claimsFor(agent: Agent, owner: Owner, scopes: Scope[]): Record<string, unknown> {
  const c: Record<string, unknown> = { sub: agent.sub, actor_type: 'agent' };
  if (scopes.includes('email')) {
    c.email = agent.handle;
    c.email_verified = true;
  }
  if (scopes.includes('profile')) {
    if (agent.name) c.name = agent.name;
    c.preferred_username = agent.preferredUsername;
    c.owner_sub = owner.ownerSub;
  }
  if (scopes.includes('owner_profile')) {
    if (owner.name) c.owner_name = owner.name;
    c.owner_verified_via = owner.verifiedVia;
  }
  if (scopes.includes('owner_email')) {
    c.owner_email = owner.email;
    c.owner_email_verified = true;
    c.owner_verified_via = owner.verifiedVia;
  }
  return c;
}

export async function mintIdToken(ctx: IssuerContext, p: { agent: Agent; owner: Owner; client: Client; scopes: Scope[]; nonce: string; authTime: number }): Promise<string> {
  const now = ctx.now();
  const claims = claimsFor(p.agent, p.owner, p.scopes);
  return new SignJWT({ ...claims, nonce: p.nonce, scope: p.scopes.join(' '), auth_time: p.authTime })
    .setProtectedHeader({ alg: ctx.signingKey.alg, kid: ctx.signingKey.kid, typ: 'JWT' })
    .setIssuer(ctx.issuer)
    .setAudience(p.client.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + ctx.constants.T_TOKEN)
    .setJti(randomSecret())
    .sign(ctx.signingKey.privateKey);
}

/** Section 3.3: UserInfo with live state. */
export async function userinfo(ctx: IssuerContext, bearer: string | null): Promise<Record<string, unknown>> {
  if (!bearer) throw invalidToken();
  const t = await ctx.store.getAccessToken(sha256(bearer));
  if (!t || t.revoked || ctx.now() >= t.expiresAt) throw invalidToken();
  const key = await ctx.store.getKey(t.kid);
  if (!key || key.status !== 'active' || ctx.now() >= key.expiresAt) throw invalidToken();
  const agent = await ctx.store.getAgent(t.handle);
  const owner = agent && (await ctx.store.getOwner(agent.ownerId));
  if (!agent || !agent.enabled || !owner) throw invalidToken();
  const account = await ctx.store.getAccount(t.handle, t.clientId);
  if (account?.status === 'disabled') throw invalidToken();
  return { iss: ctx.issuer, ...claimsFor(agent, owner, t.scopes), scope: t.scopes.join(' ') };
}

export { nowSeconds };
