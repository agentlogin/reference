// The per-sign-in record (state, nonce, PKCE verifier, the Issuer the request was sent to) travels in an encrypted,
// HttpOnly cookie. A shared server-side store separately records whether the callback has been consumed.
// Encryption: direct A256GCM with a key derived from
// the application's secret.
import { EncryptJWT, jwtDecrypt } from 'jose';
import { createHash } from 'node:crypto';

export interface PendingSignIn {
  state: string;
  nonce: string;
  verifier: string;
  /** Issuer Identifier the Authentication Request was sent to (Section 5.7 step 1). */
  issuer: string;
  /** Expected handle sent as login_hint, bound to this state and checked against returned email (Section 2.5). */
  loginHint?: string;
  /** Where the application wants the user sent after sign-in (same-origin path only). */
  returnTo?: string;
}

const keyOf = (secret: string): Uint8Array => {
  if (secret.length < 32) throw new Error('stateSecret must be at least 32 characters');
  return createHash('sha256').update(`agentlogin-rp-state|${secret}`).digest();
};

export async function seal(secret: string, p: PendingSignIn, ttlSeconds: number): Promise<string> {
  return new EncryptJWT({ ...p })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .encrypt(keyOf(secret));
}

export async function unseal(secret: string, token: string): Promise<PendingSignIn | null> {
  try {
    const { payload } = await jwtDecrypt(token, keyOf(secret), { keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'] });
    const { state, nonce, verifier, issuer, loginHint, returnTo } = payload as Record<string, unknown>;
    if (typeof state !== 'string' || typeof nonce !== 'string' || typeof verifier !== 'string' || typeof issuer !== 'string') return null;
    return { state, nonce, verifier, issuer, loginHint: typeof loginHint === 'string' ? loginHint : undefined, returnTo: typeof returnTo === 'string' ? returnTo : undefined };
  } catch {
    return null;
  }
}
