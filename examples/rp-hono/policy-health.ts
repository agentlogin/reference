import { TrustedProviderPolicy } from '@agentlogin/rp';
import { checkIssuerIdentifier, parseHandle, safeFetch } from 'agentlogin';

const POLICY_URL = 'https://agentlogin.github.io/reference/trusted-providers/v1.json';
const WARNING_MS = 2 * 60 * 60 * 1000;
const CACHE_MS = 30_000;

/** Optional operational probe. It does not change this application's issuer acceptance policy. */
export function providerPolicyHealth(options: {
  issuer: string;
  handle: string;
  /** Trusted test overrides only. */
  now?: () => number;
  fetch?: typeof safeFetch;
}): () => Promise<boolean> {
  const issuer = checkIssuerIdentifier(options.issuer);
  if (new URL(issuer).protocol !== 'https:') throw new Error('Policy monitoring requires an HTTPS issuer');
  parseHandle(options.handle);
  const now = options.now ?? Date.now;
  const request = options.fetch ?? safeFetch;
  let body: Buffer | undefined;
  let latestTime = -1;
  let cached: { healthy: boolean; until: number } | undefined;
  let running: Promise<boolean> | undefined;
  const time = () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0 || value < latestTime) throw new Error('Invalid monitor clock');
    latestTime = value;
    return value;
  };
  const policy = new TrustedProviderPolicy({
    url: POLICY_URL,
    now: time,
    fetch: async (url, settings) => {
      const response = await request(url, settings);
      body = response.body;
      return response;
    },
  });

  const check = async (): Promise<boolean> => {
    try {
      await policy.assertAccepted(issuer, options.handle);
      // These bytes have just passed the actual consumer's full schema, transport,
      // revision, current-time and exact issuer/domain acceptance checks.
      if (!body) throw new Error('No validated policy');
      const feed = JSON.parse(body.toString('utf8')) as {
        expiresAt: string;
        providers: Array<{ issuer: string; reviewExpiresAt: string }>;
      };
      const provider = feed.providers.find((entry) => entry.issuer === issuer);
      if (!provider) throw new Error('Provider missing');
      const warningAt = Math.min(Date.parse(feed.expiresAt), Date.parse(provider.reviewExpiresAt)) - WARNING_MS;
      const checkedAt = time();
      const healthy = checkedAt < warningAt;
      cached = { healthy, until: healthy ? Math.min(checkedAt + CACHE_MS, warningAt) : checkedAt + 5_000 };
      return healthy;
    } catch {
      // Raw network responses and errors never become a public health response.
      try { cached = { healthy: false, until: time() + 5_000 }; } catch { cached = undefined; }
      return false;
    }
  };

  return async () => {
    let current: number;
    try { current = time(); } catch { return false; }
    if (cached && current < cached.until) return cached.healthy;
    if (!running) {
      const attempt = check();
      running = attempt;
      void attempt.finally(() => { if (running === attempt) running = undefined; });
    }
    return running;
  };
}
