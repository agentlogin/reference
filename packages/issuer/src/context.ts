import type { Constants } from './constants.js';
import type { Store } from './store.js';
import type { CryptoKey, JWK } from 'jose';

export interface SigningKey { privateKey: CryptoKey; publicJwk: JWK; kid: string; alg: 'ES256' }

export interface IssuerContext {
  /** Issuer Identifier, https URL without trailing slash. */
  issuer: string;
  /** Section 2.4 `handle_domains`. */
  handleDomains: string[];
  constants: Constants;
  store: Store;
  signingKey: SigningKey;
  /** Locally provisioned private material; active authority is always read from Store. */
  signingKeys: Map<string, SigningKey>;
  jwksCacheSeconds: number;
  ownerDeletionRetentionSeconds: number;
  policyUri: string;
  /** Development only: http/loopback clients, private addresses in fetches, http issuer identifier. */
  allowInsecureClients: boolean;
  /** Admin bearer token for the bootstrap API and as RFC 7591 initial access token. */
  adminToken: string;
  now: () => number;
  /**
   * Delivers the one-time code of the Owner email sign-in (Section 7.5 `email`) to the Owner's address. The sign-in is
   * unavailable when absent. The code is a credential: an implementation sends it to the mailbox and nowhere else.
   */
  sendOwnerCode?: (m: { email: string; code: string; expiresAt: number }) => void | Promise<void>;
}
