// Small helpers shared by the issuer: randomness, hashing, time, handles, Accept negotiation.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const b64u = (buf: Uint8Array): string => Buffer.from(buf).toString('base64url');

/** Random bearer secret: 256 bits, base64url (N_ENTROPY is 128 bits). */
export const randomSecret = (): string => b64u(randomBytes(32));
/** Random identifier: 128 bits, base64url, 22 characters. */
export const randomId = (): string => b64u(randomBytes(16));
export const sha256 = (s: string): string => createHash('sha256').update(s).digest('base64url');
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Section 2.1: local "@" domain; local is RFC 5322 dot-atom-text, ASCII; domain as lower-case A-labels. */
export interface Handle { handle: string; local: string; domain: string }
const ATEXT = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function parseHandle(input: string): Handle | null {
  if (typeof input !== 'string' || input.length > 254) return null;
  const at = input.lastIndexOf('@');
  if (at <= 0 || at === input.length - 1) return null;
  const local = input.slice(0, at);
  const domain = input.slice(at + 1).toLowerCase();
  if (Buffer.byteLength(local) > 64 || !ATEXT.test(local)) return null;
  if (domain.length > 253) return null;
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  return { handle: `${local}@${domain}`, local, domain };
}
/** Equality per Section 2.1: local octet-equal, domains equal after lower-casing. */
export function handlesEqual(a: string, b: string): boolean {
  const pa = parseHandle(a);
  const pb = parseHandle(b);
  return !!pa && !!pb && pa.local === pb.local && pa.domain === pb.domain;
}
/** Section 2.4 `handle_domains`: exact match, or `*.example.com` matching one or more labels below example.com. */
export function domainServed(domain: string, handleDomains: string[]): boolean {
  return handleDomains.some((d) => (d.startsWith('*.') ? domain.endsWith(d.slice(1)) && domain.length > d.length - 1 : d === domain));
}

/** Section 5.3: JSON is chosen when application/json is the highest-weighted acceptable type and outranks text/html. */
export function prefersJson(accept: string | undefined): boolean {
  if (!accept) return false;
  let json = 0;
  let html = 0;
  for (const part of accept.split(',')) {
    const [typeRaw, ...params] = part.trim().split(';');
    const type = (typeRaw ?? '').trim().toLowerCase();
    let q = 1;
    for (const p of params) {
      const [k, v] = p.trim().split('=');
      if (k?.trim() === 'q' && v !== undefined) q = Number.parseFloat(v) || 0;
    }
    if (type === 'application/json') json = Math.max(json, q);
    else if (type === 'text/html') html = Math.max(html, q);
    else if (type === 'application/*') json = Math.max(json, q * 0.999);
    else if (type === 'text/*') html = Math.max(html, q * 0.999);
    else if (type === '*/*') {
      json = Math.max(json, q * 0.998);
      html = Math.max(html, q * 0.998);
    }
  }
  return json > 0 && json > html;
}

export function parseBearer(authorization: string | undefined): string | null {
  if (!authorization) return null;
  const m = /^Bearer\s+([A-Za-z0-9\-._~+/]+=*)$/i.exec(authorization.trim());
  return m ? m[1]! : null;
}

/** Section 4.1.9 of RFC 7515: `typ` compared case-insensitively, with an implied `application/` prefix. */
export function typMatches(typ: unknown, expected: string): boolean {
  if (typeof typ !== 'string') return false;
  const t = typ.toLowerCase();
  return t === expected || t === `application/${expected}`;
}

/** Serialises operations per key so that concurrent requests on one transaction are processed one at a time. */
export class Locks {
  private chains = new Map<string, Promise<unknown>>();
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.chains.get(key) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    const settled = next.then(() => undefined, () => undefined);
    this.chains.set(key, settled);
    try {
      return await next;
    } finally {
      if (this.chains.get(key) === settled) this.chains.delete(key);
    }
  }
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
