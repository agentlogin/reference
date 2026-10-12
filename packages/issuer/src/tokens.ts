// Section 5.6 (Token Endpoint), Section 3 (ID Token, UserInfo).
import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import type { IssuerContext } from './context.js';
import { OAuthError, invalidToken } from './errors.js';
import type { Agent, Client, Owner } from './store.js';
import { nowSeconds, randomSecret, safeEqual, sha256 } from './util.js';
import { subjectState } from './state.js';
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
  const fail = () => new OAuthError(400, 'invalid_grant');
  const hash = sha256(r.code);
  const code = await ctx.store.getCode(hash);
  if (!code) throw fail();
  // What this request must prove, none of which changes any state: the client, the redirect URI, the verifier.
  if (code.clientId !== client.clientId || code.redirectUri !== r.redirectUri) throw fail();
  const challenge = createHash('sha256').update(r.codeVerifier, 'ascii').digest('base64url');
  if (!safeEqual(challenge, code.codeChallenge)) throw fail();

  // The redemption itself is one atomic operation with its preconditions: not used, not void, not expired. Of
  // several Token Requests for one code, at whatever issuer process, one redeems it.
  const redeemed = await ctx.store.redeemCode(hash, ctx.now());
  if (redeemed === 'used') {
    await ctx.store.revokeAccessTokens({ txnId: code.txnId }); // Section 5.4: a code presented twice
    throw fail();
  }
  if (redeemed !== 'ok') throw fail();

  // Read after the write (see state.ts): the asserting key in the same enrollment, the Agent and the Account must
  // still stand. A revocation or a disable that ran meanwhile either voided the code before it was redeemed, or is
  // seen here. On failure the code stays used.
  const subject = { handle: code.handle, kid: code.kid, keyEnrollment: code.keyEnrollment, clientId: code.clientId, agentSub: code.agentSub, agentVersion: code.agentVersion, accountVersion: code.accountVersion };
  if (await subjectState(ctx, subject)) throw fail();
  const agent = await ctx.store.getAgent(code.handle);
  const owner = agent && (await ctx.store.getOwner(agent.ownerId));
  if (!agent || !owner || agent.sub !== code.agentSub || agent.authorizationVersion !== code.agentVersion) throw fail();
  if (!ownerClaimsAvailable(owner, code.scopes)) throw fail(); // Section 6.6: never a token that omits a requested Owner Claim

  const accessToken = randomSecret();
  const now = ctx.now();
  if (!(await ctx.store.insertAccessToken({ hash: sha256(accessToken), txnId: code.txnId, ...subject, scopes: code.scopes, expiresAt: now + ctx.constants.T_TOKEN, revoked: false }, now))) throw fail();
  // Section 5.4: when the code was presented again meanwhile, the token just issued is revoked. The other request
  // marks the code and revokes what exists; this one looks after its own insert. Whichever order, the token ends revoked.
  if ((await ctx.store.getCode(hash))?.replayed) {
    await ctx.store.revokeAccessTokens({ txnId: code.txnId });
    throw fail();
  }
  const idToken = await mintIdToken(ctx, { agent, owner, client, scopes: code.scopes, nonce: code.nonce, authTime: code.authTime });
  // Signing takes time. If the key was revoked while the token was being made, it is not handed out.
  if (await subjectState(ctx, subject)) {
    await ctx.store.revokeAccessTokens({ txnId: code.txnId });
    throw fail();
  }
  return { access_token: accessToken, token_type: 'Bearer', expires_in: ctx.constants.T_TOKEN, id_token: idToken, scope: code.scopes.join(' ') };
}

/** Section 6.6: whether every Owner Claim that the scopes request can be issued for this Owner. */
export function ownerClaimsAvailable(owner: Owner, scopes: Scope[]): boolean {
  if (scopes.includes('owner_profile') && !owner.name) return false;
  if (scopes.includes('owner_email') && !(owner.email && owner.emailVerified)) return false;
  return true;
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
    c.owner_name = owner.name;
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
  // The key that asserted the sign-in, in the enrollment that asserted it: a key that expired and was enrolled again
  // is a new enrollment and does not bring this token back (Section 3.3).
  if (await subjectState(ctx, t)) throw invalidToken();
  const agent = await ctx.store.getAgent(t.handle);
  const owner = agent && (await ctx.store.getOwner(agent.ownerId));
  if (!agent || !owner || agent.sub !== t.agentSub || agent.authorizationVersion !== t.agentVersion || !agent.enabled) throw invalidToken();
  return { iss: ctx.issuer, ...claimsFor(agent, owner, t.scopes), scope: t.scopes.join(' ') };
}

export { nowSeconds };
