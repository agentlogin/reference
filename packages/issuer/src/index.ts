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
  const { d: _d, ...publicJwk } = privateJwk;
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  const privateKey = (await importJWK(privateJwk, 'ES256')) as SigningKey['privateKey'];
  return { privateKey, publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, kid, alg: 'ES256' };
}

export async function createIssuer(opts: IssuerOptions) {
  const issuer = opts.issuer.replace(/\/+$/, '');
  if (!/^https:\/\//.test(issuer) && !opts.allowInsecureClients) throw new Error('issuer must be an https URL (set allowInsecureClients for development)');
  const ctx: IssuerContext = {
    issuer,
    handleDomains: opts.handleDomains.map((d) => d.toLowerCase()),
    constants: { ...DEFAULT_CONSTANTS, ...opts.constants },
    store: opts.store ?? new MemoryStore(),
    signingKey: await loadSigningKey(opts.signingJwk),
    allowInsecureClients: opts.allowInsecureClients ?? false,
    adminToken: opts.adminToken ?? randomSecret(),
    now: opts.now ?? nowSeconds,
    sendOwnerCode: opts.sendOwnerCode,
  };
  return { app: createIssuerApp(ctx), ctx };
}

export { MemoryStore, DEFAULT_CONSTANTS };
export type { Store, Constants, IssuerContext };
export * from './store.js';
export { safeFetch, isBlockedAddress } from './safefetch.js';
export { parseHandle, handlesEqual, prefersJson } from './util.js';
