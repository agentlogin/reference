import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { checkIssuerIdentifier, parseHandle, safeFetch } from 'agentlogin';
import { RelyingPartyError } from './errors.js';

export const AGENTLOGIN_TRUSTED_PROVIDERS_URL = 'https://agentlogin.github.io/reference/trusted-providers/v1.json';
export const AGENTLOGIN_TRUSTED_PROVIDERS_PROFILE = 'agent-login-core-1.0-draft-0.2-direct-es256';
const MAX_BYTES = 64 * 1024;
const MAX_PROVIDERS = 100;
const MAX_LIFETIME = 24 * 60 * 60 * 1000;
const CACHE_MS = 60 * 1000;
const PROGRAMME = 'agentlogin-trusted-providers';
const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const unavailable = (cause?: unknown) => new RelyingPartyError('issuer_policy_unavailable', 'the trusted-provider policy is unavailable', undefined, { cause });
const refused = () => new RelyingPartyError('issuer_not_accepted', 'this application does not accept that provider and handle domain');

export interface TrustedProviderPolicyOptions {
  /** Exact HTTPS publication URL selected by the application operator, never by login parameters. */
  url: string;
  /** Trusted application/test override. It must preserve safeFetch's transport protections; never accept it from request input. */
  fetch?: typeof safeFetch;
  /** Trusted application/test clock override, in Unix milliseconds. Production clocks must be synchronized. */
  now?: () => number;
}

/** Trusted application code that determines issuer acceptance in addition to normal protocol validation. */
export interface IssuerAcceptancePolicy {
  assertAccepted(issuer: string, handle?: string): Promise<void>;
}

interface Provider { issuer: string; handleDomains: Set<string>; reviewExpiresAt: number }
interface Snapshot { revision: number; digest: string; issuedAt: number; expiresAt: number; refreshAt: number; providers: Map<string, Provider> }

function exactKeys(value: Record<string, unknown>, keys: string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error('unexpected policy fields');
}

function httpsUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('https://') || /[\s\\\x00-\x1f\x7f]/.test(value)) throw new Error('invalid HTTPS URL');
  const url = new URL(value);
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || value.includes('#')) throw new Error('invalid HTTPS URL');
  return value;
}

function timestamp(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) throw new Error('invalid policy timestamp');
  const parsed = Date.parse(value);
  const canonical = value.replace(/(?:\.(\d{1,3}))?Z$/, (_, fraction: string | undefined) => `.${(fraction ?? '').padEnd(3, '0')}Z`);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== canonical) throw new Error('invalid policy timestamp');
  return parsed;
}

function domain(value: unknown): string {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase() || isIP(value) || domainToASCII(value) !== value) throw new Error('invalid handle domain');
  const labels = value.split('.');
  if (labels.length < 2 || !labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('invalid handle domain');
  return value;
}

function parseFeed(bytes: Buffer, now: number, requestedAt: number): Snapshot & { status: 'draft' | 'active' } {
  if (bytes.byteLength > MAX_BYTES) throw new Error('policy too large');
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!object(value)) throw new Error('invalid policy');
  exactKeys(value, ['version', 'programme', 'profile', 'status', 'revision', 'issuedAt', 'expiresAt', 'providers']);
  if (value.version !== 1 || value.programme !== PROGRAMME || value.profile !== AGENTLOGIN_TRUSTED_PROVIDERS_PROFILE || (value.status !== 'draft' && value.status !== 'active') ||
      !Number.isSafeInteger(value.revision) || (value.revision as number) <= 0 || !Array.isArray(value.providers) || value.providers.length > MAX_PROVIDERS) throw new Error('invalid policy');
  if (value.status === 'draft' && value.providers.length !== 0) throw new Error('draft policy must be empty');
  const issuedAt = timestamp(value.issuedAt);
  const expiresAt = timestamp(value.expiresAt);
  if (issuedAt > now || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_LIFETIME) throw new Error('policy is not current');
  const providers = new Map<string, Provider>();
  const domains = new Set<string>();
  for (const entry of value.providers) {
    if (!object(entry)) throw new Error('invalid provider');
    exactKeys(entry, ['issuer', 'handleDomains', 'specRevision', 'reviewUrl', 'reviewExpiresAt']);
    const issuer = checkIssuerIdentifier(httpsUrl(entry.issuer));
    if (providers.has(issuer) || !Array.isArray(entry.handleDomains) || entry.handleDomains.length === 0 || entry.handleDomains.length > 100) throw new Error('invalid provider');
    if (typeof entry.specRevision !== 'string' || !/^[a-f0-9]{40}$/.test(entry.specRevision)) throw new Error('invalid specification revision');
    httpsUrl(entry.reviewUrl); // Evidence is a reference only; it is never fetched by this policy.
    const handleDomains = new Set<string>();
    for (const item of entry.handleDomains) {
      const name = domain(item);
      if (domains.has(name)) throw new Error('duplicate handle domain');
      domains.add(name);
      handleDomains.add(name);
    }
    providers.set(issuer, { issuer, handleDomains, reviewExpiresAt: timestamp(entry.reviewExpiresAt) });
  }
  return { status: value.status, revision: value.revision as number, digest: createHash('sha256').update(bytes).digest('hex'),
    issuedAt, expiresAt, refreshAt: Math.min(requestedAt + CACHE_MS, expiresAt), providers };
}

/**
 * An explicitly selected HTTPS publisher is the trust root. This is an acceptance policy, not discovery:
 * the RP must still verify the handle's discovered issuer, metadata, callback binding and token claims.
 * Every refresh failure fails closed once the previous 60-second cache interval ends. Absolute publication
 * and review expiry are never renewed by a fetch. Revision and clock rollback checks cover this instance;
 * they are not durable across restarts or shared across hosts. Absolute expiry bounds cold-start rollback.
 * Requests ask intermediaries to revalidate, but HTTP request cache directives are advisory (RFC 9111
 * Section 5.2.1). Publication/CDN propagation can still return an older, unexpired release: 60 seconds
 * bounds this instance's cache, not global suspension delivery. HTTP headers never renew the body expiry.
 */
export class TrustedProviderPolicy implements IssuerAcceptancePolicy {
  private readonly url: string;
  private readonly fetch: typeof safeFetch;
  private readonly now: () => number;
  private snapshot?: Snapshot;
  private loading?: Promise<void>;
  private highWater?: { revision: number; digest: string };
  private observedAt = Number.NEGATIVE_INFINITY;

  constructor(options: TrustedProviderPolicyOptions) {
    this.url = new URL(httpsUrl(options.url)).href;
    this.fetch = options.fetch ?? safeFetch;
    this.now = options.now ?? Date.now;
  }

  private time(): number {
    const now = this.now();
    if (!Number.isSafeInteger(now) || now < 0 || now < this.observedAt) throw unavailable();
    this.observedAt = now;
    return now;
  }

  private async refresh(requestedAt: number): Promise<void> {
    try {
      const response = await this.fetch(this.url, { maxBytes: MAX_BYTES, timeoutMs: 10_000, maxRedirects: 0, allowPrivate: false, accept: 'application/json', headers: { 'cache-control': 'no-cache' } });
      if (response.status !== 200 || response.url !== this.url || response.redirects.length !== 0 || !Buffer.isBuffer(response.body)) throw new Error('policy fetch failed');
      const next = parseFeed(response.body, this.time(), requestedAt);
      if (this.highWater && (next.revision < this.highWater.revision ||
          (next.revision === this.highWater.revision && next.digest !== this.highWater.digest))) throw new Error('policy revision rollback or reuse');
      this.highWater = { revision: next.revision, digest: next.digest };
      if (next.status === 'draft') {
        this.snapshot = undefined;
        throw new Error('policy is not active');
      }
      this.snapshot = next;
    } catch (cause) {
      throw unavailable(cause);
    }
  }

  /** Require a current admission for this exact issuer and the presented or verified handle domain. */
  async assertAccepted(issuer: string, handle?: string): Promise<void> {
    const parsed = handle === undefined ? null : parseHandle(handle);
    if (!parsed) throw refused();
    try { checkIssuerIdentifier(httpsUrl(issuer)); } catch { throw refused(); }
    const requestedAt = this.time();
    if (!this.snapshot || requestedAt >= this.snapshot.refreshAt || requestedAt >= this.snapshot.expiresAt) {
      if (!this.loading) {
        const loading = this.refresh(requestedAt);
        this.loading = loading;
        // Clear only this attempt. All concurrent callers share its success or failure.
        void loading.finally(() => { if (this.loading === loading) this.loading = undefined; }).catch(() => {});
      }
      await this.loading;
    }
    const now = this.time();
    const snapshot = this.snapshot;
    if (!snapshot || now >= snapshot.refreshAt || now >= snapshot.expiresAt || now < snapshot.issuedAt) throw unavailable();
    const provider = snapshot.providers.get(issuer);
    if (!provider || now >= provider.reviewExpiresAt || !provider.handleDomains.has(parsed.domain)) throw refused();
  }
}

/** Opt in to the AgentLogin programme's fixed HTTPS publisher. This does not promote catalog candidates. */
export function agentLoginTrustedProviders(): TrustedProviderPolicy {
  return new TrustedProviderPolicy({ url: AGENTLOGIN_TRUSTED_PROVIDERS_URL });
}
