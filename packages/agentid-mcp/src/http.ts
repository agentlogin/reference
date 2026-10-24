export const API_ORIGIN = 'https://api.agentmail.to';
export const ISSUER = 'https://auth.agentid.com';
export type ErrorCode = 'not_configured' | 'credential_missing' | 'invalid_input' | 'busy' | 'rate_limited' | 'provider_refused' | 'provider_not_found' | 'provider_unavailable' | 'invalid_response' | 'request_uncertain' | 'operation_expired';
export class AdapterError extends Error { constructor(readonly code: ErrorCode) { super(code); } }
export const publicError = (error: unknown) => ({ error: error instanceof AdapterError ? error.code : 'invalid_response', completedApplicationLogin: false });

/** The injectable transport is for trusted embedding/tests, never operator config or tool arguments. */
export class AgentMailApi {
  private active = 0;
  private readonly starts: number[] = [];
  constructor(private readonly credential: string | undefined, private readonly fetcher: typeof fetch = globalThis.fetch) {}

  redact(value: string): string {
    return (this.credential ? value.split(this.credential).join('[redacted]') : value).replace(/am_[A-Za-z0-9_-]{8,}/g, '[redacted]');
  }
  async request(path: string, method: 'GET' | 'POST' = 'GET', body?: object, attempt?: string): Promise<Record<string, unknown>> {
    if (!this.credential || !/^[\x21-\x7e]{16,4096}$/.test(this.credential)) throw new AdapterError('credential_missing');
    if (!path.startsWith('/v0/') || path.includes('\\') || new URL(path, API_ORIGIN).origin !== API_ORIGIN) throw new AdapterError('invalid_input');
    const now = Date.now();
    while (this.starts.length && this.starts[0]! <= now - 60_000) this.starts.shift();
    if (this.active >= 2) throw new AdapterError('busy');
    if (this.starts.length >= 30) throw new AdapterError('rate_limited');
    this.starts.push(now); this.active++;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const headers: Record<string, string> = { authorization: `Bearer ${this.credential}`, accept: 'application/json' };
      if (body) headers['content-type'] = 'application/json';
      if (attempt) headers['Idempotency-Key'] = attempt;
      const response = await this.fetcher(`${API_ORIGIN}${path}`, { method, headers, ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'manual', signal: controller.signal });
      // Never follow a redirect, including same-origin redirects. Never expose provider error bodies.
      if (response.status !== (method === 'POST' ? 202 : 200)) {
        await response.body?.cancel();
        if (response.status === 429) throw new AdapterError('rate_limited');
        if ([401, 403].includes(response.status)) throw new AdapterError('provider_refused');
        if (response.status === 404) throw new AdapterError('provider_not_found');
        throw new AdapterError(method === 'POST' ? 'request_uncertain' : 'provider_unavailable');
      }
      if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') || Number(response.headers.get('content-length') ?? 0) > 64 * 1024) {
        await response.body?.cancel(); throw new AdapterError('invalid_response');
      }
      const reader = response.body?.getReader();
      if (!reader) throw new AdapterError('invalid_response');
      const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const part = await reader.read(); if (part.done) break;
          size += part.value.byteLength;
          if (size > 64 * 1024) { await reader.cancel(); throw new AdapterError('invalid_response'); }
          chunks.push(part.value);
        }
      } finally { reader.releaseLock(); }
      const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AdapterError('invalid_response');
      return value as Record<string, unknown>;
    } catch (error) {
      if (error instanceof AdapterError) throw error;
      throw new AdapterError(method === 'POST' ? 'request_uncertain' : 'provider_unavailable');
    } finally { clearTimeout(timeout); this.active--; }
  }
}
