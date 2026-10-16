import { randomUUID } from 'node:crypto';
import { ConfigSchema, identifier, uuid, type Config } from './config.js';
import { AdapterError, AgentMailApi, ISSUER } from './http.js';

type Operation = { application: string; acceptDisclosure: boolean; started: number; apiKeyId?: string; result?: Record<string, unknown>; inFlight?: Promise<Record<string, unknown>> };
type Cursor = { kind: 'apps' | 'accounts'; token: string; expires: number };
const instant = (value: unknown) => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined;
const id = (value: unknown) => uuid.safeParse(value).success ? (value as string).toLowerCase() : undefined;

export class AgentIdRuntime {
  readonly config: Config;
  private readonly api: AgentMailApi;
  private readonly operations = new Map<string, Operation>();
  private readonly cursors = new Map<string, Cursor>();
  constructor(config: Config, options: { env?: NodeJS.ProcessEnv; fetch?: typeof fetch } = {}) {
    this.config = ConfigSchema.parse(config);
    this.api = new AgentMailApi((options.env ?? process.env)[this.config.credentialEnv], options.fetch);
  }
  inventory() {
    return { provider: 'AgentID by AgentMail', issuer: ISSUER, inbox: this.config.inbox, protocol: 'agentid_oidc', applications: Object.entries(this.config.applications).map(([application, app]) => ({ application, ...app, name: this.text(app.name, 128) })), browserCompletionRequired: true, completedApplicationLogin: false };
  }
  private app(application: string) {
    if (!identifier.safeParse(application).success || !Object.hasOwn(this.config.applications, application)) throw new AdapterError('not_configured');
    return this.config.applications[application]!;
  }
  private text(value: unknown, max = 512) { return typeof value === 'string' ? this.api.redact(value).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max) : undefined; }
  private opaqueId(value: unknown) { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,256}$/.test(value) && this.api.redact(value) === value ? value : undefined; }
  private appView(value: unknown) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AdapterError('invalid_response');
    const v = value as Record<string, unknown>, appId = id(v.app_id);
    if (!appId) throw new AdapterError('invalid_response');
    return { appId, configuredAs: Object.entries(this.config.applications).find(([, a]) => a.appId === appId)?.[0] ?? null, name: this.text(v.name, 128), description: this.text(v.description), providerTextIsUntrusted: true };
  }
  private prune() {
    for (const [key, value] of this.operations) if (!value.inFlight && value.started < Date.now() - 15 * 60_000) this.operations.delete(key);
    for (const [key, value] of this.cursors) if (value.expires <= Date.now()) this.cursors.delete(key);
  }
  private page(kind: Cursor['kind'], cursor?: string) {
    this.prune(); if (!cursor) return 'limit=20';
    const value = this.cursors.get(cursor);
    if (!uuid.safeParse(cursor).success || !value || value.kind !== kind) throw new AdapterError('invalid_input');
    return `limit=20&page_token=${encodeURIComponent(value.token)}`;
  }
  private next(kind: Cursor['kind'], token: unknown) {
    if (token === undefined || token === null) return undefined;
    if (typeof token !== 'string' || !token.length || token.length > 2048 || /[\x00-\x1f\x7f]/.test(token)) throw new AdapterError('invalid_response');
    if (this.cursors.size >= 128) this.cursors.delete(this.cursors.keys().next().value!);
    const cursor = randomUUID(); this.cursors.set(cursor, { kind, token, expires: Date.now() + 15 * 60_000 }); return cursor;
  }
  async listApps(cursor?: string) {
    const result = await this.api.request(`/v0/apps?${this.page('apps', cursor)}`);
    if (!Array.isArray(result.apps) || result.apps.length > 100) throw new AdapterError('invalid_response');
    return { apps: result.apps.map((app) => this.appView(app)), nextCursor: this.next('apps', result.next_page_token), listingGrantsAccess: false };
  }
  async getApp(application: string) {
    const app = this.app(application), result = this.appView(await this.api.request(`/v0/apps/${app.appId}`));
    if (result.appId !== app.appId) throw new AdapterError('invalid_response');
    return result;
  }
  async connect(application: string, attempt: string, acceptDisclosure: boolean) {
    const app = this.app(application);
    if (!uuid.safeParse(attempt).success || typeof acceptDisclosure !== 'boolean') throw new AdapterError('invalid_input');
    this.prune();
    let operation = this.operations.get(attempt);
    if (operation && (operation.application !== application || operation.acceptDisclosure !== acceptDisclosure)) throw new AdapterError('invalid_input');
    if (!operation) {
      if (this.operations.size >= 64) throw new AdapterError('busy');
      operation = { application, acceptDisclosure, started: Date.now() }; this.operations.set(attempt, operation);
    }
    if (operation.result) {
      if (Date.parse(operation.result.expiresAt as string) <= Date.now()) throw new AdapterError('operation_expired');
      return operation.result;
    }
    if (operation.inFlight) return operation.inFlight;
    const work = async () => {
      const response = await this.api.request(`/v0/apps/${app.appId}/connect`, 'POST', { inbox_id: this.config.inbox, accept_disclosure: acceptDisclosure }, attempt);
      const apiKeyId = this.opaqueId(response.api_key_id), expiresAt = instant(response.expires_at);
      if (!apiKeyId || !expiresAt || Date.parse(expiresAt) <= Date.now() || Date.parse(expiresAt) > Date.now() + 360_000) throw new AdapterError('invalid_response');
      const raw = response.magic_url;
      if (typeof raw !== 'string' || raw.length > 4096 || !raw.startsWith(`${ISSUER}/`) || /[\\#\x00-\x20\x7f]/.test(raw) || this.api.redact(raw) !== raw) throw new AdapterError('invalid_response');
      let handoff: URL; try { handoff = new URL(raw); } catch { throw new AdapterError('invalid_response'); }
      if (handoff.origin !== ISSUER || handoff.username || handoff.password || handoff.hash) throw new AdapterError('invalid_response');
      operation!.apiKeyId = apiKeyId;
      operation!.result = { operation: attempt, application, inbox: this.config.inbox, status: 'browser_handoff', browserHandoffUrl: raw, expiresAt, sensitiveSingleUseUrl: true, completedApplicationLogin: false, applicationSession: 'not_observed' };
      return operation!.result;
    };
    operation.inFlight = work();
    try { return await operation.inFlight; } finally { operation.inFlight = undefined; }
  }
  async status(operationId: string) {
    this.prune();
    const operation = this.operations.get(operationId);
    if (!uuid.safeParse(operationId).success || !operation?.apiKeyId) throw new AdapterError('operation_expired');
    const response = await this.api.request(`/v0/api-keys/${encodeURIComponent(operation.apiKeyId)}`);
    if (response.api_key_id !== operation.apiKeyId || response.type !== 'public_key' || response.inbox_id !== this.config.inbox || (response.status !== 'pending' && response.status !== 'active')) throw new AdapterError('invalid_response');
    return { operation: operationId, application: operation.application, credentialStatus: response.status, expiresAt: instant(response.expires_at), completedApplicationLogin: false, applicationSession: 'not_observed' };
  }
  async accounts(cursor?: string) {
    const response = await this.api.request(`/v0/inboxes/${encodeURIComponent(this.config.inbox)}/accounts?${this.page('accounts', cursor)}`);
    if (!Array.isArray(response.accounts) || response.accounts.length > 100) throw new AdapterError('invalid_response');
    const accounts = response.accounts.flatMap((raw: unknown) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new AdapterError('invalid_response');
      const account = raw as Record<string, unknown>;
      const appId = id(account.app_id), accountId = id(account.account_id);
      if (account.inbox_id !== this.config.inbox || !appId || !accountId || (account.status !== undefined && account.status !== 'disabled')) throw new AdapterError('invalid_response');
      const application = Object.entries(this.config.applications).find(([, app]) => app.appId === appId)?.[0];
      if (!application) return [];
      return [{ application, accountId, status: account.status === 'disabled' ? 'disabled' : 'not_disabled', firstSignedInAt: instant(account.first_signed_in_at), lastSignedInAt: instant(account.last_signed_in_at), signInCount: typeof account.sign_in_count === 'number' && Number.isSafeInteger(account.sign_in_count) && account.sign_in_count >= 0 ? account.sign_in_count : undefined }];
    });
    return { accounts, nextCursor: this.next('accounts', response.next_page_token), applicationSession: 'not_observed' };
  }
}
