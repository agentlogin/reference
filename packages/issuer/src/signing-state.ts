import type { JWK } from 'jose';
import { DEFAULT_CONSTANTS } from './constants.js';

/** Pre-history issuers may have used any Core-permitted JWKS cache lifetime. */
export const LEGACY_SIGNING_CACHE_SECONDS = DEFAULT_CONSTANTS.T_CACHE;
export const LEGACY_SIGNING_OVERLAP_SECONDS = DEFAULT_CONSTANTS.T_TOKEN + LEGACY_SIGNING_CACHE_SECONDS;

export interface PublishedSigningKey {
  kid: string;
  publicJwk: JWK;
  status: 'published' | 'retired' | 'compromised';
  publishedAt: number;
  /** Maximum declared JWKS freshness while this key was published; never shortened. */
  cacheLifetime: number;
  /** Latest expiration reserved before signing, including attempts interrupted by crashes. */
  lastIssuedExpiresAt?: number;
  /** Legacy overlap floor; only new issuance can extend it by the unknown historical maximum cache lifetime. */
  retireNotBefore?: number;
}
export interface SigningKeyPublication { kid: string; publicJwk: JWK }

export function validateSigningPublication(input: SigningKeyPublication): void {
  const k = input.publicJwk;
  if (!input.kid || !k || k.kty !== 'EC' || k.crv !== 'P-256' || !k.x || !k.y || k.d !== undefined ||
    Object.keys(k).some((name) => !['kty','crv','x','y'].includes(name))) throw new TypeError('Signing publication must contain only an ES256 public key');
}
export function samePublicSigningKey(a: JWK, b: JWK): boolean {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}
