// Section 2.2 fetch protections for every request to a URL learned through discovery (shared with the issuer).
// time limits, no credentials. Used for Client ID Metadata Documents (Section 4.2) and, by the client
// library, for discovery. Implemented over node:https so that the resolved address can be filtered
// before the connection is made.
import { isIP } from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';

export interface SafeFetchOptions {
  maxBytes: number;
  timeoutMs: number;
  /** Development only: permit loopback and private addresses, and plain http. */
  allowPrivate?: boolean;
  accept?: string;
  /** Maximum redirects to follow (each hop re-checked); 0 treats a 3xx as the final response. Only GET requests follow redirects. */
  maxRedirects?: number;
  /** Request method, default GET. */
  method?: string;
  /** Extra request headers (for example Authorization for the Token or UserInfo Endpoint, Sections 3.3 and 5.6). */
  headers?: Record<string, string>;
  /** Request body for non-GET requests. */
  body?: string;
}
export interface SafeFetchResult {
  url: string;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  /** Status and headers of every redirect that was followed, in order. Their caching terms bound the result's too. */
  redirects: Array<{ status: number; headers: http.IncomingHttpHeaders }>;
}

const V4_BLOCKED: Array<[number, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([a, bits]) => [v4ToInt(a as string), bits as number]);

function v4ToInt(a: string): number {
  return a.split('.').reduce((acc, o) => ((acc << 8) | Number(o)) >>> 0, 0);
}
function v4Blocked(addr: string): boolean {
  const n = v4ToInt(addr);
  return V4_BLOCKED.some(([net, bits]) => bits === 0 || (n >>> (32 - bits)) === (net >>> (32 - bits)));
}
function expandV6(addr: string): bigint {
  // returns the 128-bit value; handles :: and embedded IPv4
  let a = addr;
  const v4 = /:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (v4) {
    const n = v4ToInt(v4[1]!);
    a = a.slice(0, v4.index) + `:${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, tail = ''] = a.split('::');
  const hs = head ? head.split(':') : [];
  const ts = tail ? tail.split(':') : [];
  const groups = [...hs, ...new Array(8 - hs.length - ts.length).fill('0'), ...ts];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || '0', 16)), 0n);
}
/** IPv6 is default-deny: only global unicast (2000::/3) outside the special-purpose blocks, or an embedded IPv4 address that passes the IPv4 check. */
function v6Blocked(addr: string): boolean {
  const n = expandV6(addr);
  const inRange = (prefix: string, bits: number) => (n >> BigInt(128 - bits)) === (expandV6(prefix) >> BigInt(128 - bits));
  if (inRange('::ffff:0:0', 96) || inRange('64:ff9b::', 96)) return v4Blocked(intToV4(Number(n & 0xffffffffn)));
  if (inRange('2002::', 16)) return v4Blocked(intToV4(Number((n >> 80n) & 0xffffffffn)));
  if (!inRange('2000::', 3)) return true;
  return inRange('2001::', 23) || inRange('2001:db8::', 32) || inRange('3fff::', 20);
}
function intToV4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
/** True when the address is special-use per RFC 6890 and must not be connected to. */
export function isBlockedAddress(addr: string): boolean {
  const fam = isIP(addr);
  if (fam === 4) return v4Blocked(addr);
  if (fam === 6) return v6Blocked(addr);
  return true;
}

function filteredLookup(allowPrivate: boolean): LookupFunction {
  return (hostname, options, callback) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) return callback(err, [] as never);
      const list = (addresses as dns.LookupAddress[]).filter((a) => allowPrivate || !isBlockedAddress(a.address));
      if (list.length === 0) return callback(new Error(`blocked address for ${hostname}`), [] as never);
      if ((options as { all?: boolean }).all) return callback(null, list as never);
      return callback(null, list[0]!.address as never, list[0]!.family as never);
    });
  };
}

function one(url: URL, o: SafeFetchOptions): Promise<SafeFetchResult> {
  return new Promise((resolve, reject) => {
    const allowPrivate = !!o.allowPrivate;
    if (url.protocol !== 'https:' && !(allowPrivate && url.protocol === 'http:')) return reject(new Error('scheme not permitted'));
    if (url.username || url.password) return reject(new Error('userinfo not permitted'));
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(host) && !allowPrivate && isBlockedAddress(host)) return reject(new Error('blocked address literal'));
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(
      url,
      {
        method: o.method ?? 'GET',
        headers: {
          accept: o.accept ?? 'application/json',
          'user-agent': 'agentlogin/0.1',
          ...(o.body !== undefined ? { 'content-length': String(Buffer.byteLength(o.body)) } : {}),
          ...o.headers,
        },
        lookup: filteredLookup(allowPrivate),
        timeout: o.timeoutMs,
        agent: false, // never reuse a socket another caller opened without the address check
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > o.maxBytes) {
            req.destroy(new Error('response too large'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve({ url: url.href, status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), redirects: [] }));
        res.on('error', reject);
      },
    );
    // `timeout` above is an idle timeout; this bounds the whole exchange (N_FETCH).
    const hard = setTimeout(() => req.destroy(new Error('fetch timed out')), o.timeoutMs);
    req.on('close', () => clearTimeout(hard));
    req.on('timeout', () => req.destroy(new Error('fetch timed out')));
    req.on('error', reject);
    req.end(o.body);
  });
}

export async function safeFetch(input: string | URL, o: SafeFetchOptions): Promise<SafeFetchResult> {
  const deadline = Date.now() + o.timeoutMs;
  let url = new URL(input);
  let hops = 0;
  const redirects: SafeFetchResult['redirects'] = [];
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('fetch timed out');
    const res = await one(url, { ...o, timeoutMs: remaining });
    const isGet = (o.method ?? 'GET').toUpperCase() === 'GET';
    if (isGet && res.status >= 300 && res.status < 400 && (o.maxRedirects ?? 0) > hops && res.headers.location) {
      hops += 1;
      redirects.push({ status: res.status, headers: res.headers });
      url = new URL(res.headers.location, url);
      continue;
    }
    return { ...res, redirects };
  }
}

const T_CACHE = 86_400; // seconds, Section 1.5
type HeaderMap = Record<string, string | string[] | undefined>;
const first = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v.join(', ') : v);

/**
 * Freshness lifetime in seconds that a response allows (RFC 9111 Section 4.2), capped at T_CACHE: 0 for no-store or
 * no-cache; otherwise max-age less Age; otherwise Expires less Date; `fallback` only when the response states
 * neither. A max-age or Expires that does not parse means the response is already stale.
 */
export function freshness(headers: HeaderMap, fallback: number): number {
  const cc = first(headers['cache-control']) ?? '';
  if (/(?:^|,)\s*(?:no-store|no-cache)\b/i.test(cc)) return 0;
  const age = Math.max(0, Number.parseInt(first(headers.age) ?? '0', 10) || 0);
  const m = /(?:^|,)\s*max-age\s*=\s*("?)([^",]*)\1/i.exec(cc);
  if (m) {
    const value = m[2]!.trim();
    return /^\d+$/.test(value) ? Math.max(0, Math.min(Number(value), T_CACHE) - age) : 0;
  }
  const expires = first(headers.expires);
  if (expires !== undefined) {
    const at = Date.parse(expires);
    if (Number.isNaN(at)) return 0;
    const date = Date.parse(first(headers.date) ?? '');
    return Math.max(0, Math.min(Math.floor((at - (Number.isNaN(date) ? Date.now() : date)) / 1000), T_CACHE) - age);
  }
  return Math.min(fallback, T_CACHE);
}
