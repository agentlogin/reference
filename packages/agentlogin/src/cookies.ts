// A small cookie jar for the Relying Party session the agent obtains after sign-in. Cookies are scoped by host
// and path; Secure cookies are sent over https only. Not sent to the Issuer: Agent Clients carry no cookies there.
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { parseHandle } from './handle.js';
import { agentloginHome } from './keystore.js';
import { readPrivateJson, withFileLock, writePrivateJson } from './files.js';

export interface Cookie { name: string; value: string; host: string; path: string; secure: boolean; expires?: number }
export interface CookieJar {
  store(url: URL, setCookie: string[]): Promise<void>;
  header(url: URL): Promise<string | undefined>;
  list(host?: string): Promise<Cookie[]>;
  clear(host?: string): Promise<void>;
}

function parseSetCookie(url: URL, line: string): Cookie | null {
  const parts = line.split(';').map((p) => p.trim());
  const [nv, ...attrs] = parts;
  const eq = nv!.indexOf('=');
  if (eq <= 0) return null;
  const c: Cookie = { name: nv!.slice(0, eq).trim(), value: nv!.slice(eq + 1).trim(), host: url.hostname, path: '/', secure: false };
  for (const a of attrs) {
    const [k, v] = a.split('=');
    const key = k!.trim().toLowerCase();
    if (key === 'path' && v) c.path = v.trim();
    else if (key === 'secure') c.secure = true;
    else if (key === 'max-age' && v) c.expires = Date.now() + Number(v) * 1000;
    else if (key === 'expires' && v && c.expires === undefined) c.expires = Date.parse(v);
    // Domain attributes are ignored: cookies stay host-only.
  }
  if (c.path === '' || !c.path.startsWith('/')) c.path = '/';
  return c;
}

export class MemoryCookieJar implements CookieJar {
  private cookies: Cookie[] = [];
  protected async load(): Promise<Cookie[]> { return this.cookies; }
  /** Applies one change to the stored cookies. Overridden where the store is shared between processes. */
  protected async update(fn: (all: Cookie[]) => Cookie[]): Promise<void> { this.cookies = fn(this.cookies); }

  async store(url: URL, setCookie: string[]) {
    const incoming = setCookie.map((line) => parseSetCookie(url, line)).filter((c): c is Cookie => c !== null);
    if (incoming.length === 0) return;
    await this.update((all) => {
      const now = Date.now();
      let next = all.filter((c) => c.expires === undefined || c.expires > now);
      for (const c of incoming) {
        next = next.filter((x) => !(x.name === c.name && x.host === c.host && x.path === c.path));
        if (c.expires === undefined || c.expires > now) next.push(c);
      }
      return next;
    });
  }
  async header(url: URL) {
    const now = Date.now();
    const match = (await this.load()).filter((c) => c.host === url.hostname && (c.expires === undefined || c.expires > now) && (!c.secure || url.protocol === 'https:') && (url.pathname === c.path || url.pathname.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`)));
    return match.length ? match.map((c) => `${c.name}=${c.value}`).join('; ') : undefined;
  }
  async list(host?: string) { const now = Date.now(); return (await this.load()).filter((c) => (!host || c.host === host) && (c.expires === undefined || c.expires > now)); }
  async clear(host?: string) { await this.update((all) => (host ? all.filter((c) => c.host !== host) : [])); }
}

/**
 * A cookie jar in a private file, for one Agent. Sessions belong to the Agent that obtained them: use `forHandle`,
 * which names the file by a hash of the handle (the local part is case-sensitive, the domain is not, and a file
 * system may fold case). Changes are locked across processes.
 */
export class FileCookieJar extends MemoryCookieJar {
  constructor(public readonly path: string) { super(); }
  static forHandle(handle: string): FileCookieJar {
    const h = parseHandle(handle);
    if (!h) throw new Error(`not a handle: ${handle}`);
    return new FileCookieJar(join(agentloginHome(), 'cookies', `${createHash('sha256').update(h.handle, 'utf8').digest('hex')}.json`));
  }
  protected override async load(): Promise<Cookie[]> { return readPrivateJson<Cookie[]>(this.path, []); }
  protected override async update(fn: (all: Cookie[]) => Cookie[]): Promise<void> {
    await withFileLock(this.path, () => writePrivateJson(this.path, fn(readPrivateJson<Cookie[]>(this.path, []))));
  }
}
