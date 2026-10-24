// Public API of the reference issuer.
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { DEFAULT_CONSTANTS, type Constants } from './constants.js';
import type { IssuerContext, SigningKey } from './context.js';
import { MemoryStore, type Store } from './store.js';
import { createIssuerApp } from './app.js';
import { randomSecret, nowSeconds } from './util.js';

export interface IssuerOptions {
  /** Issuer Identifier, e.g. https://issuer.example (no trailing slash). */
  issuer: string;
  handleDomains: string[];
  store?: Store;
  constants?: Partial<Constants>;
  /** Private ES256 JWK; generated (ephemeral) when absent. */
  signingJwk?: JWK;
  /** Published key ring. The first key bootstraps a new database; additions remain staged until explicit activation. */
  signingJwks?: JWK[];
  jwksCacheSeconds?: number;
  ownerDeletionRetentionSeconds?: number;
  /** Published fixed retention policy. Defaults to this issuer's /policy document. */
  policyUri?: string;
  adminToken?: string;
  /** Development only: permits http/loopback clients and private addresses in fetches. */
  allowInsecureClients?: boolean;
  now?: () => number;
  /** Delivers the one-time code of the Owner email sign-in (`POST /owner/sessions/email`); the sign-in is off when absent. */
  sendOwnerCode?: IssuerContext['sendOwnerCode'];
}

export async function loadSigningKey(jwk?: JWK): Promise<SigningKey> {
  let privateJwk = jwk;
  if (!privateJwk) {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    privateJwk = await exportJWK(privateKey);
  }
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256' || typeof privateJwk.d !== 'string' ||
      (privateJwk.alg !== undefined && privateJwk.alg !== 'ES256') || (privateJwk.use !== undefined && privateJwk.use !== 'sig')) throw new TypeError('Signing key must be a private ES256 signing JWK');
  const { d: _d, ...publicJwk } = privateJwk;
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  const privateKey = (await importJWK(privateJwk, 'ES256')) as SigningKey['privateKey'];
  const verificationKey=await importJWK({kty:publicJwk.kty,crv:publicJwk.crv,x:publicJwk.x,y:publicJwk.y},'ES256') as CryptoKey;
  const probe=new TextEncoder().encode('Agent Login signing-key consistency check');
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,probe);
  if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verificationKey,signature,probe)) throw new TypeError('Signing private key does not match its public key');
  return { privateKey, publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, kid, alg: 'ES256' };
}

export async function createIssuer(opts: IssuerOptions) {
  const issuer = opts.issuer.replace(/\/+$/, '');
  if (!/^https:\/\//.test(issuer) && !opts.allowInsecureClients) throw new Error('issuer must be an https URL (set allowInsecureClients for development)');
  if (opts.signingJwk && opts.signingJwks) throw new TypeError('Supply signingJwk or signingJwks');
  if (opts.signingJwks && opts.signingJwks.length === 0) throw new TypeError('Signing ring must not be empty');
  const keys = await Promise.all((opts.signingJwks ?? [opts.signingJwk]).map(loadSigningKey));
  const constants = { ...DEFAULT_CONSTANTS, ...opts.constants };
  const jwksCacheSeconds = opts.jwksCacheSeconds ?? Math.min(3600,constants.T_CACHE);
  const ownerDeletionRetentionSeconds = opts.ownerDeletionRetentionSeconds ?? 0;
  if (!Number.isSafeInteger(jwksCacheSeconds) || jwksCacheSeconds < 0 || jwksCacheSeconds > constants.T_CACHE) throw new TypeError('JWKS cache lifetime must be between zero and T_CACHE');
  if (!Number.isSafeInteger(ownerDeletionRetentionSeconds) || ownerDeletionRetentionSeconds < 0) throw new TypeError('Owner retention period must be finite non-negative integer seconds');
  const policyUri=opts.policyUri ?? `${issuer}/policy`;
  if (new URL(policyUri).protocol !== 'https:' && !opts.allowInsecureClients) throw new TypeError('Policy URI must use HTTPS');
  const ctx: IssuerContext = {
    issuer,
    handleDomains: opts.handleDomains.map((d) => d.toLowerCase()),
    constants,
    store: opts.store ?? new MemoryStore(),
    signingKey: keys[0]!,
    signingKeys: new Map(keys.map((key) => [key.kid,key])),
    jwksCacheSeconds,
    ownerDeletionRetentionSeconds,
    policyUri,
    allowInsecureClients: opts.allowInsecureClients ?? false,
    adminToken: opts.adminToken ?? randomSecret(),
    now: opts.now ?? nowSeconds,
    sendOwnerCode: opts.sendOwnerCode,
  };
  await ctx.store.publishSigningKeys(keys.map(({kid,publicJwk}) => ({kid,publicJwk})),keys[0]!.kid,ctx.now(),jwksCacheSeconds);
  // A legacy transaction cannot prove which terms were displayed. Cancel it once at startup, preserving the
  // normal expiry precedence and fixed terminal retention; never infer acceptance from today's Client record.
  for (;;) {
    const batch = await ctx.store.listLegacyTransactions(256);
    if (batch.length === 0) break;
    for (const tx of batch) {
      const now = await ctx.store.currentTime(ctx.now());
      await ctx.store.updateTransaction({ ...tx, status: 'denied', reason: 'access_denied', terminalAt: now, challenge: undefined }, tx.version, { now });
    }
  }
  return {
    app: createIssuerApp(ctx), ctx,
    /** Validate every private key before publishing any. Reloads do not silently change the active key. */
    async publishSigningKeys(jwks: JWK[]) {
      if (jwks.length === 0) throw new TypeError('Signing ring must not be empty');
      const loaded=await Promise.all(jwks.map(loadSigningKey));
      await ctx.store.publishSigningKeys(loaded.map(({kid,publicJwk})=>({kid,publicJwk})),loaded[0]!.kid,ctx.now(),jwksCacheSeconds);
      for (const key of loaded) ctx.signingKeys.set(key.kid,key);
      return loaded.map((key)=>key.kid);
    },
    async activateSigningKey(kid: string) {
      if (!ctx.signingKeys.has(kid)) throw new Error('Provision the private key before activation');
      return ctx.store.activateSigningKey(kid,ctx.now());
    },
    async removeSigningKey(kid: string, compromised = false) {
      const removed=await ctx.store.removeSigningKey(kid,compromised,ctx.now());
      if (removed) ctx.signingKeys.delete(kid);
      return removed;
    },
  };
}

export { MemoryStore, DEFAULT_CONSTANTS };
export type { Store, Constants, IssuerContext };
export * from './store.js';
export { safeFetch, isBlockedAddress } from './safefetch.js';
export { parseHandle, handlesEqual, prefersJson } from './util.js';

export { SQLiteStore } from './sqlite-store.js';

export { ownerAddressKey } from './owner-address.js';

export * from './signing-state.js';

export { validateSigningConfiguration, reloadSigningConfiguration, type SigningConfiguration } from './signing-configuration.js';

/** Trusted service integration; authorization is atomically bound to its immutable Agent identity. */
export { enrollKey as enrollAgentKey } from './agents.js';
