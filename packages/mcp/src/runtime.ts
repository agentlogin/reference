import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { AgentLogin, AgentLoginError, FileCookieJar, FileKeystore, MemoryCookieJar, type CookieJar, type SignInAtOptions, type SignInResult, type TransactionView } from 'agentlogin';
import { z } from 'zod';
import { atPointer, checkedUrl, parseConfig, sensitiveName, type Application, type Config, type Identity } from './config.js';
import { catalogView, readCatalog, type Catalog } from './catalog.js';
import { readState, writeState } from './private-state.js';

export class ToolError extends Error { constructor(public readonly code: string, message: string) { super(message); } }
export interface LoginClient {
  discover(): Promise<{ issuer: string }>;
  signInAt(url: string, options: SignInAtOptions): Promise<SignInResult>;
  fetch(url: string, init?: RequestInit): Promise<Response>;
}
const SessionBindingSchema = z.object({ handle: z.string(), issuer: z.string(), sub: z.string().min(1).max(255) }).strict();
export type SessionBinding = z.infer<typeof SessionBindingSchema>;
interface Context { client: LoginClient; jar: CookieJar; identity: Identity; app: Application; issuer: string; bindingKey: string }
interface Job {
  id: string; identity: string; application: string; state: 'starting' | 'awaiting_consent' | 'awaiting_owner' | 'completing' | 'authenticated' | 'failed';
  expiresAt: number; finishedAt?: number; code?: string; scopes?: string[]; disclosure?: Array<{ scope: string; title: string; description: string }>;
  client?: TransactionView['client']; consentReason?: string;
  ownerTransactionId?: string;
  decide?: (decision: 'allow' | 'deny') => void;
}
export interface RuntimeOptions {
  clientFactory?: (identity: Identity, app: Application, jar: CookieJar) => LoginClient;
  jarFactory?: (identityId: string, applicationId: string) => CookieJar;
  catalogs?: Catalog[];
  sessionBindings?: { get(key: string): Promise<SessionBinding | undefined>; set(key: string, value: SessionBinding | undefined): Promise<void> };
}
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const publicErrors = new Set(['no_key', 'timeout', 'key_revoked', 'owner_declined', 'access_denied', 'consent_required', 'signup_limit_reached', 'login_required', 'enrollment_uncertain']);
export function safeError(error: unknown): { code: string; message: string } {
  if (error instanceof ToolError) return { code: error.code, message: error.message };
  if (error instanceof AgentLoginError && publicErrors.has(error.code)) return { code: error.code, message: 'The operation did not complete. Inspect its status and resolve the indicated condition before retrying.' };
  return { code: 'operation_failed', message: 'The operation failed. Credentials and upstream response details have been withheld.' };
}

/** Bounded JSON only: callback pages, response headers and Location values are never returned to the model. */
export async function readJson(response: Response, maxBytes = 64 * 1024): Promise<unknown> {
  if (!/^application\/(?:[\w.+-]+\+)?json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) {
    await response.body?.cancel();
    throw new ToolError('unexpected_response', 'The configured endpoint did not return JSON.');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new ToolError('unexpected_response', 'The endpoint returned no response body.');
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new ToolError('response_too_large', 'The endpoint response exceeded the configured limit.');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { await reader.cancel().catch(() => {}); }
}

function sanitized(value: unknown, secrets: string[], depth = 0): unknown {
  if (depth > 12) return '[omitted]';
  if (typeof value === 'string') {
    let result = value.slice(0, 8192);
    for (const secret of secrets) if (secret) result = result.split(secret).join('[redacted]');
    return result.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted]').replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
  }
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => sanitized(v, secrets, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100).map(([k, v]) => [k, sensitiveName(k) ? '[redacted]' : sanitized(v, secrets, depth + 1)]));
  return value;
}

export class LoginRuntime {
  readonly config: Config;
  private readonly contexts = new Map<string, Context>();
  private readonly resolvers = new Map<string, LoginClient>();
  private readonly jobs = new Map<string, Job>();
  private readonly busy = new Set<string>();
  private readonly lastStarted = new Map<string, number>();
  private readonly catalogs: Catalog[];
  private lastCall = 0;
  private callTokens = 60;

  constructor(config: unknown, private readonly options: RuntimeOptions = {}) {
    this.config = parseConfig(config);
    this.catalogs = options.catalogs ?? this.config.catalogFiles.map(readCatalog);
  }

  rateLimit(): void {
    const now = performance.now();
    this.callTokens = Math.min(60, this.callTokens + (now - this.lastCall) / 1000);
    this.lastCall = now;
    if (this.callTokens < 1) throw new ToolError('rate_limited', 'Too many calls; wait at least one second.');
    this.callTokens -= 1;
  }

  inventory() {
    return {
      identities: Object.entries(this.config.identities).map(([id, v]) => ({ id, handle: v.handle, enrollmentAvailable: !!v.enrollmentEndpoint })),
      applications: Object.entries(this.config.applications).map(([id, v]) => ({ id, name: v.name, origin: v.origin, operations: Object.entries(v.operations).map(([name, op]) => ({ name, description: op.description, method: op.method, inputFields: op.inputFields, queryFields: op.queryFields ?? [] })) })),
      sessionLocation: 'local_helper', browserSession: false,
    };
  }
  catalog(kind?: 'provider' | 'application') { return { entries: catalogView(this.catalogs).filter((e) => !kind || e.kind === kind), automaticTrust: false }; }

  private key(identity: string, application: string) { return `${identity}:${application}`; }
  private configuredPair(identityId: string, appId: string) {
    const identity = Object.hasOwn(this.config.identities, identityId) ? this.config.identities[identityId] : undefined;
    const app = Object.hasOwn(this.config.applications, appId) ? this.config.applications[appId] : undefined;
    if (!identity || !app) throw new ToolError('not_configured', 'Choose an identity and application from agentlogin_inventory.');
    return { identity, app };
  }
  private async context(identityId: string, appId: string): Promise<Context> {
    const { identity, app } = this.configuredPair(identityId, appId);
    let resolver = this.resolvers.get(identityId);
    if (!resolver) {
      resolver = this.options.clientFactory?.(identity, app, new MemoryCookieJar()) ?? new AgentLogin({ handle: identity.handle, issuer: identity.issuer, allowInsecure: this.config.developmentLoopback, timeoutMs: 10_000 });
      this.resolvers.set(identityId, resolver);
    }
    // The SDK applies the protocol's bounded discovery cache on each call. A context never pins
    // an unconfigured issuer forever simply because it was the first one seen by this process.
    const { issuer } = await resolver.discover();
    checkedUrl(issuer, this.config.developmentLoopback);
    const key = this.key(identityId, appId);
    const found = this.contexts.get(key);
    if (found?.issuer === issuer) return found;
    const digest = createHash('sha256').update(JSON.stringify([identity.handle, issuer, app.origin, appId])).digest('hex');
    const jar = this.options.jarFactory?.(identityId, appId) ?? new FileCookieJar(join(this.config.stateDirectory, 'sessions', `${digest}.json`));
    const client = this.options.clientFactory?.({ ...identity, issuer }, app, jar) ?? new AgentLogin({ handle: identity.handle, issuer, keystore: new FileKeystore(join(this.config.stateDirectory, 'keys.json')), cookies: jar, allowInsecure: this.config.developmentLoopback, timeoutMs: 10_000 });
    const context = { identity, app, jar, client, issuer, bindingKey: digest };
    this.contexts.set(key, context);
    return context;
  }
  private async binding(context: Context): Promise<SessionBinding | undefined> {
    if (this.options.sessionBindings) return this.options.sessionBindings.get(context.bindingKey);
    const value = readState(join(this.config.stateDirectory, 'sessions', `${context.bindingKey}.binding.json`));
    return value == null ? undefined : SessionBindingSchema.parse(value);
  }
  private async bind(context: Context, value?: SessionBinding) {
    if (this.options.sessionBindings) return this.options.sessionBindings.set(context.bindingKey, value);
    writeState(join(this.config.stateDirectory, 'sessions', `${context.bindingKey}.binding.json`), value ?? null);
  }

  private prune() {
    const now = Date.now();
    for (const [id, job] of this.jobs) if (job.finishedAt && now - job.finishedAt > 15 * 60_000) this.jobs.delete(id);
    while (this.jobs.size >= 128) {
      const terminal = [...this.jobs.values()].find((j) => j.finishedAt);
      if (!terminal) break;
      this.jobs.delete(terminal.id);
    }
  }

  start(identity: string, application: string) {
    this.prune();
    this.configuredPair(identity, application);
    const key = this.key(identity, application);
    const existing = [...this.jobs.values()].find((job) => this.key(job.identity, job.application) === key && !job.finishedAt);
    if (existing) return this.status(existing.id);
    if (this.busy.has(key) || this.busy.size >= 4) throw new ToolError('busy', 'Another operation is in progress. Wait for its result.');
    if (Date.now() - (this.lastStarted.get(key) ?? 0) < 5000) throw new ToolError('rate_limited', 'Wait five seconds before starting another sign-in.');
    this.lastStarted.set(key, Date.now());
    const job: Job = { id: randomUUID(), identity, application, state: 'starting', expiresAt: Date.now() + this.config.signInTimeoutSeconds * 1000 };
    this.jobs.set(job.id, job); this.busy.add(key);
    void this.complete(job).finally(() => this.busy.delete(key));
    return this.status(job.id);
  }

  status(operation: string) {
    this.prune();
    const job = this.jobs.get(operation);
    if (!job) throw new ToolError('unknown_operation', 'The operation is unknown or its retained status has expired.');
    const identity = this.config.identities[job.identity]!;
    const ownerPortal = job.state === 'awaiting_owner' ? identity.ownerPortal : undefined;
    const ownerApprovalUrl = ownerPortal && identity.ownerApprovalPath && job.ownerTransactionId ? new URL(identity.ownerApprovalPath.replace('{transaction_id}', encodeURIComponent(job.ownerTransactionId)), ownerPortal).href : undefined;
    return { operation: job.id, identity: job.identity, application: job.application, status: job.state, expiresAt: job.expiresAt, ...(job.code ? { error: job.code } : {}), ...(job.scopes ? { scopes: job.scopes } : {}), ...(job.disclosure ? { disclosure: job.disclosure, client: job.client, consentReason: job.consentReason, disclosureIsUntrustedText: true } : {}), ...(ownerPortal ? { ownerPortal } : {}), ...(job.state === 'awaiting_owner' && job.ownerTransactionId ? { transactionId: job.ownerTransactionId } : {}), ...(ownerApprovalUrl ? { ownerApprovalUrl } : {}), sessionLocation: 'local_helper', browserSession: false, ...(!job.finishedAt ? { pollAfterSeconds: 2 } : {}) };
  }

  review(operation: string, decision: 'allow' | 'deny') {
    const job = this.jobs.get(operation);
    if (!job || job.state !== 'awaiting_consent' || !job.decide || Date.now() >= job.expiresAt) throw new ToolError('review_not_pending', 'This operation has no live disclosure review.');
    const resolve = job.decide;
    delete job.decide; job.state = 'starting';
    resolve(decision);
    return this.status(operation);
  }

  private async complete(job: Job) {
    try {
      const context = await this.context(job.identity, job.application);
      if (Date.now() >= job.expiresAt) throw new ToolError('timeout', 'Sign-in exceeded its deadline.');
      // A failed fresh callback cannot be mistaken for the old account just because its handle matches.
      // Forgetting a local jar is not server-side revocation; use logout to invalidate its server session.
      await this.bind(context);
      await context.jar.clear();
      const result = await context.client.signInAt(new URL(context.app.loginPath, context.app.origin).href, {
        expectedHost: new URL(context.app.origin).host,
        deadlineMs: Math.max(1, job.expiresAt - Date.now()), acceptDisclosure: false,
        onReview: (transaction) => this.awaitReview(job, transaction),
        onOwnerApproval: (transaction) => {
          if (typeof transaction.transaction_id !== 'string' || !transaction.transaction_id || transaction.transaction_id.length > 512 || /[\x00-\x20\x7f]/.test(transaction.transaction_id)) throw new ToolError('invalid_transaction', 'The issuer returned an invalid transaction identifier.');
          job.ownerTransactionId = transaction.transaction_id;
          job.state = 'awaiting_owner';
        },
      });
      if (result.issuer !== context.issuer || result.handle !== context.identity.handle) throw new ToolError('session_mismatch', 'Sign-in returned a different identity binding.');
      job.state = 'completing';
      let url = checkedUrl(result.redirectUrl, this.config.developmentLoopback);
      for (let hop = 0; hop <= 5; hop += 1) {
        if (Date.now() >= job.expiresAt) throw new ToolError('timeout', 'Sign-in exceeded its deadline.');
        if (url.origin !== context.app.origin) throw new ToolError('callback_rejected', 'The callback left the configured application origin.');
        const response = await context.client.fetch(url.href, { signal: AbortSignal.timeout(Math.max(1, job.expiresAt - Date.now())) });
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (response.status >= 300 && response.status < 400 && location) {
          if (hop === 5) throw new ToolError('callback_rejected', 'The callback exceeded the redirect limit.');
          url = checkedUrl(new URL(location, url).href, this.config.developmentLoopback);
          continue;
        }
        if (response.status < 200 || response.status >= 300) throw new ToolError('callback_failed', 'The application rejected the sign-in callback.');
        break;
      }
      if (Date.now() >= job.expiresAt) throw new ToolError('timeout', 'Sign-in exceeded its deadline.');
      const binding = await this.checkSession(context, job.expiresAt, true);
      if (Date.now() >= job.expiresAt) throw new ToolError('timeout', 'Sign-in exceeded its deadline.');
      await this.bind(context, binding);
      job.scopes = result.scopes; job.state = 'authenticated';
    } catch (error) { job.state = 'failed'; job.code = safeError(error).code; }
    finally { job.finishedAt = Date.now(); job.decide?.('deny'); delete job.decide; delete job.disclosure; delete job.client; delete job.consentReason; }
  }

  private awaitReview(job: Job, transaction: TransactionView): Promise<'allow' | 'deny'> {
    job.state = 'awaiting_consent';
    job.scopes = transaction.requested_scopes.filter((s) => typeof s === 'string').map((s) => s.slice(0, 128));
    job.disclosure = transaction.disclosure.slice(0, 32).map((d) => ({ scope: d.scope.slice(0, 128), title: d.title.slice(0, 256), description: d.description.slice(0, 2048) }));
    const plain = (value: string, max: number) => String(sanitized(value, [])).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max);
    const publicUrl = (value?: string) => {
      if (!value || value.length > 2048) return undefined;
      try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : undefined; } catch { return undefined; }
    };
    job.client = { client_id: plain(transaction.client.client_id, 2048), client_type: plain(transaction.client.client_type, 64), redirect_host: plain(transaction.client.redirect_host, 300), ...(transaction.client.client_name ? { client_name: plain(transaction.client.client_name, 256) } : {}), ...(publicUrl(transaction.client.tos_uri) ? { tos_uri: publicUrl(transaction.client.tos_uri) } : {}), ...(publicUrl(transaction.client.policy_uri) ? { policy_uri: publicUrl(transaction.client.policy_uri) } : {}) };
    job.consentReason = transaction.consent_reason ? plain(transaction.consent_reason, 64) : undefined;
    return new Promise((resolve) => { job.decide = resolve; });
  }

  private async checkSession(context: Context, deadline = Date.now() + 10_000, freshSignIn = false): Promise<SessionBinding> {
    const expected = freshSignIn ? undefined : await this.binding(context);
    if (!freshSignIn && !expected) throw new ToolError('not_authenticated', 'This helper has no bound session for the current issuer. Sign in again.');
    const response = await context.client.fetch(new URL(context.app.sessionCheck.path, context.app.origin).href, { signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())) });
    if (response.status !== 200) { await response.body?.cancel(); throw new ToolError('not_authenticated', 'The application has no matching active session.'); }
    const value = await readJson(response);
    const checked = SessionBindingSchema.safeParse({ handle: atPointer(value, context.app.sessionCheck.handlePointer), issuer: atPointer(value, context.app.sessionCheck.issuerPointer), sub: atPointer(value, context.app.sessionCheck.subjectPointer) });
    if (!checked.success || checked.data.handle !== context.identity.handle || checked.data.issuer !== context.issuer || (expected && (expected.handle !== checked.data.handle || expected.issuer !== checked.data.issuer || expected.sub !== checked.data.sub))) throw new ToolError('session_mismatch', 'The application session does not match the requested immutable identity.');
    return checked.data;
  }

  async request(identity: string, application: string, operation: string, input?: Record<string, unknown>) {
    const context = await this.context(identity, application);
    const configured = Object.hasOwn(context.app.operations, operation) ? context.app.operations[operation] : undefined;
    if (!configured) throw new ToolError('not_configured', 'Choose an operation from agentlogin_inventory.');
    const body = input ?? {};
    const allowedFields = configured.method === 'GET' ? configured.queryFields ?? [] : configured.inputFields;
    if (Object.keys(body).some((key) => !allowedFields.includes(key))) throw new ToolError('invalid_input', 'Input contains a field this operation does not accept.');
    if (configured.method === 'GET' && Object.values(body).some((value) => typeof value !== 'string')) throw new ToolError('invalid_input', 'Query inputs must be strings.');
    if (Buffer.byteLength(JSON.stringify(body)) > 32 * 1024) throw new ToolError('input_too_large', 'Input exceeds 32 KiB.');
    const target = new URL(configured.path, context.app.origin);
    if (configured.method === 'GET') for (const [field, value] of Object.entries(body)) target.searchParams.set(field, value as string);
    return this.exclusive(identity, application, async () => {
      await this.checkSession(context);
      const before = (await context.jar.list()).map((cookie) => cookie.value);
      const response = await context.client.fetch(target.href, { method: configured.method, ...(configured.method !== 'GET' ? { headers: { 'content-type': 'application/json', origin: context.app.origin }, body: JSON.stringify(body) } : {}) });
      // Do not retry, follow a Location, expose headers or label a failed remote write as successful.
      if (response.status >= 300) { await response.body?.cancel(); return { status: response.status, succeeded: false, retryAutomatically: false }; }
      const selected: Record<string, unknown> = {};
      if (Object.keys(configured.output).length && response.status !== 204) {
        const json = await readJson(response);
        const secrets = [...before, ...(await context.jar.list()).map((cookie) => cookie.value)];
        for (const [field, pointer] of Object.entries(configured.output)) {
          const value = atPointer(json, pointer);
          if (value !== undefined) selected[field] = sanitized(value, secrets);
        }
      } else await response.body?.cancel();
      return { status: response.status, succeeded: response.status >= 200 && response.status < 300, data: selected, dataIsUntrusted: true };
    });
  }

  async logout(identity: string, application: string) {
    const context = await this.context(identity, application);
    return this.exclusive(identity, application, async () => {
      if (!context.app.logoutPath) throw new ToolError('logout_unavailable', 'No application logout endpoint is configured; local forgetting would not revoke the server session.');
      const response = await context.client.fetch(new URL(context.app.logoutPath, context.app.origin).href, { method: 'POST', headers: { origin: context.app.origin } });
      await response.body?.cancel();
      if (response.status < 200 || response.status >= 300) throw new ToolError('logout_failed', 'The application did not confirm logout. The session has been retained for retry.');
      await context.jar.clear();
      await this.bind(context);
      return { loggedOut: true, application, identity, browserSession: false };
    });
  }

  private async exclusive<T>(identity: string, application: string, fn: () => Promise<T>): Promise<T> {
    const key = this.key(identity, application);
    if (this.busy.has(key) || this.busy.size >= 4) throw new ToolError('busy', 'Another operation is in progress. Wait for its result.');
    this.busy.add(key);
    try { return await fn(); } finally { this.busy.delete(key); }
  }

  /** Useful to an embedding host during graceful shutdown and to deterministic integration tests. */
  async settled(operation: string): Promise<ReturnType<LoginRuntime['status']>> {
    while (!this.jobs.get(operation)?.finishedAt) {
      if (!this.jobs.has(operation)) throw new ToolError('unknown_operation', 'Unknown operation.');
      await delay(5);
    }
    return this.status(operation);
  }
}
