// A minimal Agent Client: holds a P-256 key, enrolls it (Section 7.2) and signs assertions (Section 6.3).
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { randomBytes } from 'node:crypto';
import { call, obj } from './http.js';

export const rnd = (n = 16) => randomBytes(n).toString('base64url');

export class AgentClient {
  private constructor(
    public readonly handle: string,
    public readonly privateKey: CryptoKey,
    public readonly publicJwk: JWK,
    public readonly kid: string,
  ) {}

  static async generate(handle: string): Promise<AgentClient> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const pub = await exportJWK(publicKey);
    const jwk: JWK = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
    return new AgentClient(handle, privateKey, jwk, await calculateJwkThumbprint(jwk, 'sha256'));
  }

  /** Enroll and prove the key with the management API. */
  async enroll(issuer: string, agentsEndpoint: string, credential: string, name = 'conformance'): Promise<{ enroll: Awaited<ReturnType<typeof call>>; proof: Awaited<ReturnType<typeof call>> }> {
    const enroll = await call(`${agentsEndpoint}/${encodeURIComponent(this.handle)}/keys`, { method: 'POST', headers: { authorization: `Bearer ${credential}` }, json: { jwk: this.publicJwk, name } });
    const e = obj(enroll.json);
    const now = Math.floor(Date.now() / 1000);
    const proofJws = await new SignJWT({ nonce: e.challenge, jti: rnd() })
      .setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: this.kid })
      .setIssuer(this.handle)
      .setSubject(this.handle)
      .setAudience(issuer)
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(this.privateKey);
    const proof = e.proof_url ? await call(e.proof_url, { method: 'POST', json: { proof: proofJws } }) : enroll;
    return { enroll, proof };
  }

  /** Signs an assertion; `mutate` lets a check corrupt header or payload. */
  async assertion(issuer: string, txn: { transaction_id: string; challenge: string }, extra: Record<string, unknown> = {}, mutate: { header?: Record<string, unknown>; payload?: Record<string, unknown>; iat?: number; exp?: number } = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = { txn: txn.transaction_id, nonce: txn.challenge, jti: rnd(), ...extra, ...mutate.payload };
    const header: Record<string, unknown> = { alg: 'ES256', typ: 'agent-login+jwt', kid: this.kid, ...mutate.header };
    return new SignJWT(payload)
      .setProtectedHeader(header as never)
      .setIssuer((mutate.payload?.iss as string) ?? this.handle)
      .setSubject((mutate.payload?.sub as string) ?? this.handle)
      .setAudience((mutate.payload?.aud as string) ?? issuer)
      .setIssuedAt(mutate.iat ?? now)
      .setExpirationTime(mutate.exp ?? now + 60)
      .sign(this.privateKey);
  }
}
