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

/** RFC 6265 Section 5.1.4: the default path of a cookie is the directory of the URL that set it. */
function defaultPath(pathname: string): string {
  if (!pathname.startsWith('/')) return '/';
  const last = pathname.lastIndexOf('/');
  return last === 0 ? '/' : pathname.slice(0, last);
}

function parseSetCookie(url: URL, line: string): Cookie | null {
  const parts = line.split(';').map((p) => p.trim());
  const [nv, ...attrs] = parts;
  const eq = nv!.indexOf('=');
  if (eq <= 0) return null;
  // Without a usable Path attribute a cookie belongs to the directory that set it, not to the whole host: a cookie
  // from /private/login is not sent to /public, and two applications on one host do not see each other's cookies.
  const c: Cookie = { name: nv!.slice(0, eq).trim(), value: nv!.slice(eq + 1).trim(), host: url.hostname, path: defaultPath(url.pathname), secure: false };
  for (const a of attrs) {
    const i = a.indexOf('=');
    const key = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : a.slice(i + 1).trim();
    if (key === 'path' && v.startsWith('/')) c.path = v; // Section 5.2.4: a value that does not start with "/" is ignored
    else if (key === 'secure') c.secure = true;
    else if (key === 'max-age' && /^-?\d+$/.test(v)) c.expires = Date.now() + Number(v) * 1000;
    else if (key === 'expires' && v && c.expires === undefined && !Number.isNaN(Date.parse(v))) c.expires = Date.parse(v);
    // Domain attributes are ignored: cookies stay host-only.
  }
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
        const at = next.findIndex((x) => x.name === c.name && x.host === c.host && x.path === c.path);
        // RFC 6265 5.3: replacing a cookie preserves its creation order, including after loading a file jar.
        if (c.expires !== undefined && c.expires <= now) {
          if (at >= 0) next.splice(at, 1);
        } else if (at >= 0) next[at] = c;
        else next.push(c);
      }
      return next;
    });
  }
  async header(url: URL) {
    const now = Date.now();
    const match = (await this.load()).filter((c) => c.host === url.hostname && (c.expires === undefined || c.expires > now) && (!c.secure || url.protocol === 'https:') && (url.pathname === c.path || url.pathname.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`)));
    // RFC 6265 5.4: longest paths first; stable sort preserves earlier creation order for equal paths.
    match.sort((a, b) => b.path.length - a.path.length);
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
    await withFileLock(this.path, (guard) => writePrivateJson(this.path, fn(readPrivateJson<Cookie[]>(this.path, [])), guard));
  }
}
