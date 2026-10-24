import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { AgentLogin, FileKeystore, safeFetch, type StoredKey } from 'agentlogin';
import { SignJWT, importJWK } from 'jose';
import { z } from 'zod';
import { checkedUrl, type Config, type Identity } from './config.js';
import { readState, writeState } from './private-state.js';
import { safeError, ToolError } from './runtime.js';

const recordSchema = z.object({
  requestId: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/), token: z.string().min(16).max(4096), approvalUrl: z.string(), expiresAt: z.number().positive(),
  kid: z.string(), handle: z.string(), issuer: z.string(), endpoint: z.string(),
  outcome: z.enum(['active', 'denied', 'expired']).optional(),
}).strict();
type EnrollmentRecord = z.infer<typeof recordSchema>;
type Progress = { identity: string; status: 'not_started' | 'starting' | 'awaiting_owner' | 'proving' | 'active' | 'denied' | 'expired' | 'failed'; polling: boolean; resumable: boolean; approvalUrl?: string; expiresAt?: number; error?: string };
export interface EnrollmentRuntimeOptions {
  /** Clock and scheduler injection for deterministic deadline tests. */
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

/** Optional provider enrollment broker. The broker authorizes a public key; proof of possession remains Core 7.2. */
export class EnrollmentRuntime {
  private readonly running = new Map<string, Progress>();
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  constructor(private readonly config: Config, private readonly env = process.env, options: EnrollmentRuntimeOptions = {}) {
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }
  private identity(identityId: string) {
    const identity = Object.hasOwn(this.config.identities, identityId) ? this.config.identities[identityId] : undefined;
    if (!identity?.enrollmentEndpoint) throw new ToolError('enrollment_unavailable', 'This identity has no configured enrollment broker. Use the provider enrollment setup.');
    return identity;
  }
  private filename(identityId: string) {
    // Bind the durable request to the configured identity name too: editing its handle, issuer or
    // broker must not silently orphan the request and create another key under that name.
    return join(this.config.stateDirectory, 'enrollments', `${createHash('sha256').update(identityId).digest('hex')}.json`);
  }
  private saved(identityId: string, identity: Identity, issuer = identity.issuer): EnrollmentRecord | undefined {
    const endpoint = checkedUrl(identity.enrollmentEndpoint!, this.config.developmentLoopback);
    let saved = readState(this.filename(identityId));
    // Read pre-durable-status records without deleting or replacing their keys. The next explicit
    // enrollment run writes the new stable name; a status read remains read-only.
    if (saved === undefined && issuer) saved = readState(join(this.config.stateDirectory, 'enrollments', `${createHash('sha256').update(JSON.stringify([identity.handle, issuer, endpoint.href])).digest('hex')}.json`));
    if (saved === undefined) return undefined;
    const record = recordSchema.parse(saved);
    if (record.handle !== identity.handle || (issuer && record.issuer !== issuer) || record.endpoint !== endpoint.href)
      throw new ToolError('enrollment_mismatch', 'Saved enrollment no longer matches this identity configuration.');
    this.approvalUrl(record.approvalUrl, endpoint, record.requestId);
    return record;
  }
  private approvalUrl(value: string, endpoint: URL, requestId: string) {
    const approval = checkedUrl(value, this.config.developmentLoopback);
    const expected = `${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(requestId)}/approve`;
    if (approval.origin !== endpoint.origin || approval.pathname !== expected || approval.search)
      throw new ToolError('enrollment_response_invalid', 'The provider returned an unexpected approval address.');
    return approval.href;
  }
  status(identityId: string): Progress {
    const identity = this.identity(identityId);
    const current = this.running.get(identityId);
    if (current?.polling) return { ...current };
    const record = this.saved(identityId, identity);
    if (!record) return current ? { ...current } : { identity: identityId, status: 'not_started', polling: false, resumable: false };
    const status = record.outcome ?? (this.now() >= record.expiresAt * 1000 ? 'expired' : current?.status === 'failed' ? 'failed' : 'awaiting_owner');
    return { identity: identityId, status, polling: false, resumable: status === 'awaiting_owner' || status === 'failed',
      ...(status === 'awaiting_owner' ? { approvalUrl: record.approvalUrl } : {}), expiresAt: record.expiresAt,
      ...(status === 'failed' && current?.error ? { error: current.error } : {}) };
  }
  start(identityId: string) {
    const identity = this.identity(identityId);
    const existing = this.status(identityId);
    if (existing.polling || ['active', 'denied', 'expired'].includes(existing.status)) return existing;
    if ([...this.running.values()].filter((v) => v.polling).length >= 2) throw new ToolError('busy', 'Wait for a running enrollment check to finish.');
    const progress: Progress = { ...existing, status: 'starting', polling: true, resumable: false };
    delete progress.error;
    this.running.set(identityId, progress);
    void this.perform(identity, progress).catch((error) => {
      const code = safeError(error).code;
      progress.resumable = !!progress.expiresAt && this.now() < progress.expiresAt * 1000;
      progress.status = code === 'timeout' && progress.resumable ? 'awaiting_owner' : 'failed';
      if (progress.status === 'failed') progress.error = code;
    }).finally(() => { progress.polling = false; });
    return { ...progress };
  }
  private async json(url: string, init: RequestInit, deadline: number) {
    if (this.now() >= deadline) throw new ToolError('timeout', 'Enrollment exceeded its deadline.');
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, name) => { headers[name] = value; });
    const response = await safeFetch(url, { method: init.method, headers, body: typeof init.body === 'string' ? init.body : undefined, allowPrivate: this.config.developmentLoopback, timeoutMs: Math.min(10_000, deadline - this.now()), maxBytes: 64 * 1024, maxRedirects: 0 });
    return response;
  }
  private async perform(identity: Identity, progress: Progress) {
    const deadline = this.now() + this.config.signInTimeoutSeconds * 1000;
    const endpoint = checkedUrl(identity.enrollmentEndpoint!, this.config.developmentLoopback);
    const store = new FileKeystore(join(this.config.stateDirectory, 'keys.json'));
    const client = new AgentLogin({ handle: identity.handle, issuer: identity.issuer, keystore: store, allowInsecure: this.config.developmentLoopback, timeoutMs: 10_000 });
    const { issuer, metadata } = await client.discover();
    const filename = this.filename(progress.identity);
    let record = this.saved(progress.identity, identity, issuer);
    let key: StoredKey | undefined;
    if (record) {
      if (record.handle !== identity.handle || record.issuer !== issuer || record.endpoint !== endpoint.href) throw new ToolError('enrollment_mismatch', 'Saved enrollment no longer matches this identity configuration.');
      key = await store.get(record.kid);
      if (!key || key.handle !== identity.handle || key.issuer !== issuer || key.status === 'revoked') throw new ToolError('enrollment_mismatch', 'Saved enrollment key is unavailable. Do not create a replacement automatically.');
    } else {
      const keys = (await store.list(identity.handle)).filter((k) => k.issuer === issuer);
      if (keys.some((k) => k.status === 'active' && (!k.expiresAt || k.expiresAt > this.now() / 1000))) { progress.status = 'active'; return; }
      key = keys.find((k) => k.status === 'pending') ?? await client.generateKey('Agent Login local helper');
      const token = identity.enrollmentCredentialEnv ? this.env[identity.enrollmentCredentialEnv] : undefined;
      if (!token) throw new ToolError('enrollment_credential_missing', 'Configure the provider API credential through the host secret configuration.');
      const response = await this.json(endpoint.href, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ handle: identity.handle, public_jwk: key.publicJwk, name: key.name }) }, deadline);
      if (response.status !== 201 && response.status !== 200) throw new ToolError('enrollment_refused', 'The provider did not accept the enrollment request.');
      const body = JSON.parse(response.body.toString('utf8')) as Record<string, unknown>;
      const parsed = z.object({ request_id: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/), polling_token: z.string().min(16).max(4096), approval_url: z.string(), expires_at: z.number().positive() }).passthrough().parse(body);
      const approvalUrl = this.approvalUrl(parsed.approval_url, endpoint, parsed.request_id);
      record = { requestId: parsed.request_id, token: parsed.polling_token, approvalUrl, expiresAt: parsed.expires_at, kid: key.kid, handle: identity.handle, issuer, endpoint: endpoint.href };
    }
    writeState(filename, record);
    progress.approvalUrl = record.approvalUrl; progress.expiresAt = record.expiresAt; progress.status = 'awaiting_owner';
    const finish = (outcome: 'active' | 'denied' | 'expired') => {
      writeState(filename, { ...record, outcome }); progress.status = outcome; progress.resumable = false; delete progress.approvalUrl;
    };
    const attemptedChallenges = new Set<string>();
    const pollUrl = new URL(`${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(record.requestId)}`, endpoint.origin).href;
    while (this.now() < Math.min(deadline, record.expiresAt * 1000)) {
      const response = await this.json(pollUrl, { headers: { authorization: `Bearer ${record.token}`, accept: 'application/json' } }, deadline);
      if (response.status === 429) { await this.pause(5, deadline); continue; }
      if (response.status !== 200) throw new ToolError('enrollment_uncertain', 'Enrollment could not be checked. The saved key has been retained.');
      const body = JSON.parse(response.body.toString('utf8')) as { status?: string; enrollment?: { kid?: string; status?: string; challenge?: string; proof_url?: string; expires_at?: number }; retry_after?: number };
      if (body.status === 'denied' || body.status === 'expired') { finish(body.status); return; }
      if (body.status === 'approved' && body.enrollment) {
        const enrollment = body.enrollment;
        if (typeof enrollment.expires_at !== 'number' || !Number.isFinite(enrollment.expires_at) || enrollment.expires_at <= this.now() / 1000) throw new ToolError('enrollment_response_invalid', 'The provider did not return a valid key expiry.');
        if (enrollment.kid !== key.kid) throw new ToolError('enrollment_mismatch', 'The provider approved a different key.');
        if (enrollment.status === 'active') { await store.put({ ...key, status: 'active', expiresAt: enrollment.expires_at }); finish('active'); return; }
        if (enrollment.status !== 'pending' || typeof enrollment.challenge !== 'string' || !enrollment.challenge || typeof enrollment.proof_url !== 'string') throw new ToolError('enrollment_response_invalid', 'The provider did not return a complete enrollment challenge.');
        const proofUrl = checkedUrl(enrollment.proof_url, this.config.developmentLoopback);
        const agents = new URL(metadata.agents_endpoint);
        const base = agents.pathname.replace(/\/$/, '');
        if (proofUrl.origin !== agents.origin || !proofUrl.pathname.startsWith(`${base}/`) || proofUrl.search) throw new ToolError('enrollment_response_invalid', 'The proof endpoint is outside the discovered issuer agent endpoint.');
        // Never loop on a consumed or expired nonce. A later broker poll may mint a fresh proof
        // after rechecking the durable approval and the current Owner, Agent and key lifecycle.
        if (attemptedChallenges.has(enrollment.challenge)) throw new ToolError('enrollment_uncertain', 'The provider has not supplied a fresh challenge. Resume the saved request later.');
        attemptedChallenges.add(enrollment.challenge);
        const now = Math.floor(this.now() / 1000);
        const proof = await new SignJWT({ nonce: enrollment.challenge, jti: randomUUID() }).setProtectedHeader({ alg: 'ES256', typ: 'agent-login-enrollment+jwt', kid: key.kid }).setIssuer(identity.handle).setSubject(identity.handle).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60).sign(await importJWK(key.privateJwk, 'ES256'));
        progress.status = 'proving';
        // A lost answer is reconciled by the next explicit start: it polls the same durable broker request.
        const proved = await this.json(proofUrl.href, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ proof }) }, deadline).catch(() => { throw new ToolError('enrollment_uncertain', 'The proof response was lost; retry enrollment to reconcile the saved request.'); });
        if (proved.status === 400 || proved.status === 401) {
          // A short proof challenge can expire during transport. Re-poll the saved request;
          // only the broker can authorize a replacement. This does not retry Owner approval.
          progress.status = 'awaiting_owner'; await this.pause(5, deadline); continue;
        }
        if (proved.status !== 200) throw new ToolError('enrollment_uncertain', 'The proof outcome needs reconciliation; the same key and request have been retained.');
        const active = z.object({ kid: z.literal(key.kid), status: z.literal('active'), expires_at: z.number().positive() }).passthrough().safeParse(JSON.parse(proved.body.toString('utf8')));
        if (!active.success) throw new ToolError('enrollment_uncertain', 'The proof response did not confirm activation of this key. Resume the saved request.');
        await store.put({ ...key, status: 'active', expiresAt: active.data.expires_at }); finish('active'); return;
      }
      if (body.status !== 'pending') throw new ToolError('enrollment_response_invalid', 'The provider returned an unknown enrollment status.');
      await this.pause(typeof body.retry_after === 'number' ? body.retry_after : 5, deadline);
    }
    if (this.now() >= record.expiresAt * 1000) { finish('expired'); return; }
    // The local polling budget is deliberately shorter than the human decision window.
    // Pausing network activity does not deny, expire or discard the provider request.
    progress.status = 'awaiting_owner'; progress.resumable = true;
  }
  private pause(seconds: number, deadline: number) { return this.sleep(Math.max(0, Math.min(Number.isFinite(seconds) ? Math.max(1, Math.min(seconds, 60)) * 1000 : 5000, deadline - this.now()))); }
}
