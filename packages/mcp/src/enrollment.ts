import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { AgentLogin, FileKeystore, safeFetch, type StoredKey } from 'agentlogin';
import { SignJWT, importJWK } from 'jose';
import { z } from 'zod';
import { checkedUrl, type Config, type Identity } from './config.js';
import { readState, writeState } from './private-state.js';
import { safeError, ToolError } from './runtime.js';

const recordSchema = z.object({
  requestId: z.string().min(1).max(128), token: z.string().min(16).max(4096), approvalUrl: z.string(), expiresAt: z.number().positive(),
  kid: z.string(), handle: z.string(), issuer: z.string(), endpoint: z.string(),
}).strict();
type EnrollmentRecord = z.infer<typeof recordSchema>;
type Progress = { identity: string; status: 'starting' | 'awaiting_owner' | 'proving' | 'active' | 'failed'; approvalUrl?: string; expiresAt?: number; error?: string };

/** Optional provider enrollment broker. The broker authorizes a public key; proof of possession remains Core 7.2. */
export class EnrollmentRuntime {
  private readonly running = new Map<string, Progress>();
  constructor(private readonly config: Config, private readonly env = process.env) {}
  status(identity: string) { return this.running.get(identity) ?? { identity, status: 'not_started' }; }
  start(identityId: string) {
    const identity = Object.hasOwn(this.config.identities, identityId) ? this.config.identities[identityId] : undefined;
    if (!identity?.enrollmentEndpoint) throw new ToolError('enrollment_unavailable', 'This identity has no configured enrollment broker. Use the provider enrollment setup.');
    const existing = this.running.get(identityId);
    if (existing && ['starting', 'awaiting_owner', 'proving'].includes(existing.status)) return existing;
    if ([...this.running.values()].filter((v) => ['starting', 'awaiting_owner', 'proving'].includes(v.status)).length >= 2) throw new ToolError('busy', 'Wait for a pending enrollment to finish.');
    const progress: Progress = { identity: identityId, status: 'starting' };
    this.running.set(identityId, progress);
    void this.perform(identity, progress).catch((error) => { progress.status = 'failed'; progress.error = safeError(error).code; });
    return { ...progress };
  }
  private async json(url: string, init: RequestInit, deadline: number) {
    if (Date.now() >= deadline) throw new ToolError('timeout', 'Enrollment exceeded its deadline.');
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, name) => { headers[name] = value; });
    const response = await safeFetch(url, { method: init.method, headers, body: typeof init.body === 'string' ? init.body : undefined, allowPrivate: this.config.developmentLoopback, timeoutMs: Math.min(10_000, deadline - Date.now()), maxBytes: 64 * 1024, maxRedirects: 0 });
    return response;
  }
  private async perform(identity: Identity, progress: Progress) {
    const deadline = Date.now() + this.config.signInTimeoutSeconds * 1000;
    const endpoint = checkedUrl(identity.enrollmentEndpoint!, this.config.developmentLoopback);
    const store = new FileKeystore(join(this.config.stateDirectory, 'keys.json'));
    const client = new AgentLogin({ handle: identity.handle, issuer: identity.issuer, keystore: store, allowInsecure: this.config.developmentLoopback, timeoutMs: 10_000 });
    const { issuer, metadata } = await client.discover();
    const filename = join(this.config.stateDirectory, 'enrollments', `${createHash('sha256').update(JSON.stringify([identity.handle, issuer, endpoint.href])).digest('hex')}.json`);
    const saved = readState(filename);
    let record = saved === undefined ? undefined : recordSchema.parse(saved);
    let key: StoredKey | undefined;
    if (record) {
      if (record.handle !== identity.handle || record.issuer !== issuer || record.endpoint !== endpoint.href) throw new ToolError('enrollment_mismatch', 'Saved enrollment no longer matches this identity configuration.');
      key = await store.get(record.kid);
      if (!key || key.handle !== identity.handle || key.issuer !== issuer) throw new ToolError('enrollment_mismatch', 'Saved enrollment key is unavailable. Do not create a replacement automatically.');
    } else {
      const keys = (await store.list(identity.handle)).filter((k) => k.issuer === issuer);
      if (keys.some((k) => k.status === 'active' && (!k.expiresAt || k.expiresAt > Date.now() / 1000))) { progress.status = 'active'; return; }
      key = keys.find((k) => k.status === 'pending') ?? await client.generateKey('Agent Login local helper');
      const token = identity.enrollmentCredentialEnv ? this.env[identity.enrollmentCredentialEnv] : undefined;
      if (!token) throw new ToolError('enrollment_credential_missing', 'Configure the provider API credential through the host secret configuration.');
      const response = await this.json(endpoint.href, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ handle: identity.handle, public_jwk: key.publicJwk, name: key.name }) }, deadline);
      if (response.status !== 201 && response.status !== 200) throw new ToolError('enrollment_refused', 'The provider did not accept the enrollment request.');
      const body = JSON.parse(response.body.toString('utf8')) as Record<string, unknown>;
      const parsed = z.object({ request_id: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/), polling_token: z.string().min(16).max(4096), approval_url: z.string(), expires_at: z.number().positive() }).passthrough().parse(body);
      const approval = checkedUrl(parsed.approval_url, this.config.developmentLoopback);
      const expected = `${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(parsed.request_id)}/approve`;
      if (approval.origin !== endpoint.origin || approval.pathname !== expected || approval.search) throw new ToolError('enrollment_response_invalid', 'The provider returned an unexpected approval address.');
      record = { requestId: parsed.request_id, token: parsed.polling_token, approvalUrl: approval.href, expiresAt: parsed.expires_at, kid: key.kid, handle: identity.handle, issuer, endpoint: endpoint.href };
      writeState(filename, record);
    }
    progress.approvalUrl = record.approvalUrl; progress.expiresAt = record.expiresAt; progress.status = 'awaiting_owner';
    const pollUrl = new URL(`${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(record.requestId)}`, endpoint.origin).href;
    while (Date.now() < Math.min(deadline, record.expiresAt * 1000)) {
      const response = await this.json(pollUrl, { headers: { authorization: `Bearer ${record.token}`, accept: 'application/json' } }, deadline);
      if (response.status === 429) { await this.pause(5, deadline); continue; }
      if (response.status !== 200) throw new ToolError('enrollment_uncertain', 'Enrollment could not be checked. The saved key has been retained.');
      const body = JSON.parse(response.body.toString('utf8')) as { status?: string; enrollment?: { kid?: string; status?: string; challenge?: string; proof_url?: string; expires_at?: number }; retry_after?: number };
      if (body.status === 'denied' || body.status === 'expired') throw new ToolError('enrollment_refused', 'The Owner declined or the enrollment expired.');
      if (body.status === 'approved' && body.enrollment) {
        const enrollment = body.enrollment;
        if (enrollment.kid !== key.kid) throw new ToolError('enrollment_mismatch', 'The provider approved a different key.');
        if (enrollment.status === 'active') { await store.put({ ...key, status: 'active', expiresAt: enrollment.expires_at }); progress.status = 'active'; return; }
        if (typeof enrollment.challenge !== 'string' || typeof enrollment.proof_url !== 'string') throw new ToolError('enrollment_response_invalid', 'The provider did not return a complete enrollment challenge.');
        const proofUrl = checkedUrl(enrollment.proof_url, this.config.developmentLoopback);
        const agents = new URL(metadata.agents_endpoint);
        const base = agents.pathname.replace(/\/$/, '');
        if (proofUrl.origin !== agents.origin || !proofUrl.pathname.startsWith(`${base}/`)) throw new ToolError('enrollment_response_invalid', 'The proof endpoint is outside the discovered issuer agent endpoint.');
        const now = Math.floor(Date.now() / 1000);
        const proof = await new SignJWT({ nonce: enrollment.challenge, jti: randomUUID() }).setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid }).setIssuer(identity.handle).setSubject(identity.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60).sign(await importJWK(key.privateJwk, 'ES256'));
        progress.status = 'proving';
        // A lost answer is reconciled by the next explicit start: it polls the same durable broker request.
        const proved = await this.json(proofUrl.href, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ proof }) }, deadline).catch(() => { throw new ToolError('enrollment_uncertain', 'The proof response was lost; retry enrollment to reconcile the saved request.'); });
        if (proved.status !== 200) throw new ToolError('enrollment_uncertain', 'The proof outcome needs reconciliation; the same key and request have been retained.');
        await store.put({ ...key, status: 'active', expiresAt: enrollment.expires_at }); progress.status = 'active'; return;
      }
      if (body.status !== 'pending') throw new ToolError('enrollment_response_invalid', 'The provider returned an unknown enrollment status.');
      await this.pause(typeof body.retry_after === 'number' ? body.retry_after : 5, deadline);
    }
    throw new ToolError('timeout', 'Enrollment expired or reached its local deadline. The key has been retained.');
  }
  private pause(seconds: number, deadline: number) { return new Promise((resolve) => setTimeout(resolve, Math.max(0, Math.min(Number.isFinite(seconds) ? Math.max(1, Math.min(seconds, 60)) * 1000 : 5000, deadline - Date.now())))); }
}
