// A small cookie jar for the Relying Party session the agent obtains after sign-in. Cookies are scoped by host
// and path; Secure cookies are sent over https only. Not sent to the Issuer: Agent Clients carry no cookies there.
import { join } from 'node:path';
import { agentloginHome } from './keystore.js';
import { readPrivateJson, writePrivateJson } from './files.js';

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
  protected cookies: Cookie[] = [];
  protected load(): Cookie[] { return this.cookies; }
  protected save(c: Cookie[]) { this.cookies = c; }
  async store(url: URL, setCookie: string[]) {
    let all = this.load();
    for (const line of setCookie) {
      const c = parseSetCookie(url, line);
      if (!c) continue;
      all = all.filter((x) => !(x.name === c.name && x.host === c.host && x.path === c.path));
      if (c.expires === undefined || c.expires > Date.now()) all.push(c);
    }
    this.save(all);
  }
  async header(url: URL) {
    const now = Date.now();
    const match = this.load().filter((c) => c.host === url.hostname && (c.expires === undefined || c.expires > now) && (!c.secure || url.protocol === 'https:') && (url.pathname === c.path || url.pathname.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`)));
    return match.length ? match.map((c) => `${c.name}=${c.value}`).join('; ') : undefined;
  }
  async list(host?: string) { const now = Date.now(); return this.load().filter((c) => (!host || c.host === host) && (c.expires === undefined || c.expires > now)); }
  async clear(host?: string) { this.save(host ? this.load().filter((c) => c.host !== host) : []); }
}

/** One file per Agent: a session one Agent obtained is never sent on behalf of another. */
export class FileCookieJar extends MemoryCookieJar {
  constructor(public readonly path: string = join(agentloginHome(), 'cookies.json')) { super(); }
  static forHandle(handle: string): FileCookieJar {
    return new FileCookieJar(join(agentloginHome(), 'cookies', `${encodeURIComponent(handle.toLowerCase())}.json`));
  }
  protected override load(): Cookie[] { return readPrivateJson<Cookie[]>(this.path, []); }
  protected override save(c: Cookie[]) { writePrivateJson(this.path, c); }
}
