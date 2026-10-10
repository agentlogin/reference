import type { Constants } from './constants.js';
import type { Store } from './store.js';
import type { CryptoKey, JWK } from 'jose';
import type { Locks } from './util.js';

export interface SigningKey { privateKey: CryptoKey; publicJwk: JWK; kid: string; alg: 'ES256' }

export interface IssuerContext {
  /** Issuer Identifier, https URL without trailing slash. */
  issuer: string;
  /** Section 2.4 `handle_domains`. */
  handleDomains: string[];
  constants: Constants;
  store: Store;
  signingKey: SigningKey;
  /** Development only: http/loopback clients, private addresses in fetches, http issuer identifier. */
  allowInsecureClients: boolean;
  /** Admin bearer token for the bootstrap API and as RFC 7591 initial access token. */
  adminToken: string;
  now: () => number;
  locks: Locks;
}
