// A minimal application that accepts sign-ins from software agents with @agentlogin/rp.
import { Hono } from 'hono';
import { randomBytes } from 'node:crypto';
import { RelyingParty, RelyingPartyError, createHandlers, signInForm, signInFormCss, type CallbackStateStore } from '@agentlogin/rp';
import { validSid, validateNote, NoteError, type NoteCursor, type SessionStore } from './session-store.js';
import { workspaceView } from './workspace-view.js';
export type { Session } from './session-store.js';

export interface ExampleOptions {
  /** This application's public URL. */
  base: string;
  /** Issuer to accept, exactly as the Issuer publishes it. */
  issuer: string;
  stateSecret: string;
  callbackStore: CallbackStateStore;
  sessionStore: SessionStore;
  /** For local development: handle domains served by `issuer`, mapped without WebFinger. */
  handleDomains?: string[];
  now?: () => number;
  /** Runtime readiness, including storage connectivity. Must not disclose connection details. */
  ready?: () => Promise<boolean>;
}

export const SESSION_TTL = 3600; // seconds

export function createExample(o: ExampleOptions) {
  const baseUrl = new URL(o.base);
  const dev = baseUrl.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(baseUrl.hostname);
  if (baseUrl.protocol !== 'https:' && !dev) throw new TypeError('base must use HTTPS outside loopback development');
  if (baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash || baseUrl.pathname !== '/') throw new TypeError('base must be an origin URL');
  if (!o.sessionStore) throw new TypeError('sessionStore is required');
  const base = baseUrl.origin;
  const now = o.now ?? (() => Math.floor(Date.now() / 1000));
  const cookieName = dev ? 'sid' : '__Host-sid';
  const cookie = (sid: string, maxAge: number): string => `${cookieName}=${sid}; Path=/; HttpOnly; SameSite=Lax${dev ? '' : '; Secure'}; Max-Age=${maxAge}`;
  const sessionCookie = (request: Request): string | undefined => {
    const values = (request.headers.get('cookie') ?? '').split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${cookieName}=`));
    const value = values.length === 1 ? values[0]!.slice(cookieName.length + 1) : undefined;
    return validSid(value) ? value : undefined;
  };
  const rp = new RelyingParty({
    clientId: `${base}/client-metadata.json`, // an Open Client: this URL is the client identifier
    redirectUri: `${base}/auth/agent/callback`,
    issuers: [o.issuer],
    staticIssuers: Object.fromEntries((o.handleDomains ?? []).map((d) => [d, o.issuer])),
    stateSecret: o.stateSecret,
    allowInsecure: dev,
  });
  const sessionStore = o.sessionStore;
  const unavailable = () => new Response(JSON.stringify({ error: 'session_store_failed' }), {
    status: 503, headers: { 'content-type': 'application/json', 'cache-control': 'no-store, private' },
  });
  const sweep = () => sessionStore.cleanup(1000);

  const auth = createHandlers(rp, {
    callbackStore: o.callbackStore,
    metadata: { clientName: 'Agent Workspace', initiateLoginUri: `${base}/auth/agent/login`, maxSignupsPerOwner: 3 },
    onSignIn: async (signIn, request) => {
      const sid = randomBytes(32).toString('base64url');
      try {
        // Commit the account, new session and old-cookie invalidation together before issuing the cookie.
        await sessionStore.create(sid, { agent: signIn.agent, expiresAt: now() + SESSION_TTL, live: rp.liveCheckOf(signIn) }, sessionCookie(request));
      } catch {
        return unavailable(); // Includes uncertain commits: start a new sign-in, never replay this callback.
      }
      return new Response(null, { status: 302, headers: {
        location: signIn.returnTo ?? '/workspace', 'set-cookie': cookie(sid, SESSION_TTL), 'cache-control': 'no-store, private',
      } });
    },
  });

  const app = new Hono();
  app.use('*', async (c, next) => {
    await next();
    c.header('x-content-type-options', 'nosniff');
    c.header('referrer-policy', 'no-referrer');
    if (['/', '/workspace', '/me', '/notes', '/logout'].includes(c.req.path) || c.req.path.startsWith('/auth/agent/')) c.header('cache-control', 'no-store, private');
  });
  app.get('/healthz', (c) => {
    c.header('cache-control', 'no-store');
    return c.json({ status: 'alive' });
  });
  app.get('/readyz', async (c) => {
    c.header('cache-control', 'no-store');
    try {
      if (o.ready && !await o.ready()) return c.json({ status: 'unavailable' }, 503);
      return c.json({ status: 'ready' });
    } catch { return c.json({ status: 'unavailable' }, 503); }
  });
  app.get('/client-metadata.json', (c) => auth.metadata(c.req.raw));
  app.all('/auth/agent/login', (c) => auth.login(c.req.raw));
  app.get('/auth/agent/callback', (c) => auth.callback(c.req.raw));
  app.get('/workspace', (c) => {
    const nonce = randomBytes(24).toString('base64url');
    c.header('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`);
    return c.html(workspaceView(nonce));
  });

  app.get('/', (c) =>
    c.html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - Agent Workspace</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:38rem;margin:10vh auto;padding:0 24px;color:#182523;background:#f6f8f5}h1{font-size:44px;line-height:1.1;letter-spacing:-.04em}p{color:#5b6c66}code{font-size:.85em;overflow-wrap:anywhere}.card{padding:28px;border:1px solid #dce5df;border-radius:16px;background:white}a{color:#176c4e}${signInFormCss}</style></head><body>
<strong>Agent Workspace</strong><h1>A place for your agent's work.</h1>
<p>Sign in with your agent identity to save private notes across sessions.</p><div class="card">
${signInForm({ action: '/auth/agent/login' })}</div>
<p>Using an assistant? Give it this application's sign-in address:<br><code>${base}/auth/agent/login</code></p>
<p>Your agent needs a key enrolled with its identity provider. Your provider may ask its human owner to approve access.</p></body></html>`),
  );

  // Modern browser requests must be same-origin, including sibling subdomains. Agents do not send browser
  // Origin/Fetch Metadata headers. No CORS policy grants another origin access to these authenticated routes.
  const sameOrigin = (request: Request): boolean => {
    const origin = request.headers.get('origin');
    if (origin !== null && origin !== base) return false;
    const site = request.headers.get('sec-fetch-site');
    if (site !== null && site !== 'same-origin') return false;
    const referer = request.headers.get('referer');
    if (origin === null && referer !== null) {
      try { if (new URL(referer).origin !== base) return false; } catch { return false; }
    }
    return true;
  };

  app.get('/me', async (c) => {
    const sid = sessionCookie(c.req.raw);
    try {
      const s = sid ? await sessionStore.get(sid) : undefined;
      if (!s) return c.json({ error: 'not signed in' }, 401);
      return c.json({ account: s.agent.key, iss: s.agent.iss, sub: s.agent.sub, handle: s.agent.handle, name: s.agent.name, owner: s.agent.ownerKey, first_seen: s.firstSeen });
    } catch { return unavailable(); }
  });

  app.get('/notes', async (c) => {
    const sid = sessionCookie(c.req.raw);
    let before: NoteCursor | undefined;
    const query = new URL(c.req.url).searchParams;
    try {
      if (Array.from(query.keys()).some((key) => key !== 'before') || query.getAll('before').length > 1) throw new Error('invalid cursor');
      if (query.has('before')) {
        const encoded = query.get('before')!;
        if (!/^[A-Za-z0-9_-]{1,256}$/.test(encoded)) throw new Error('invalid cursor');
        const raw = Buffer.from(encoded, 'base64url');
        if (raw.toString('base64url') !== encoded) throw new Error('invalid cursor');
        const tuple = JSON.parse(raw.toString('utf8'));
        if (!Array.isArray(tuple) || tuple.length !== 2 || !Number.isSafeInteger(tuple[0]) || tuple[0] < 0 || typeof tuple[1] !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(tuple[1])) throw new Error('invalid cursor');
        before = { createdAt: tuple[0], id: tuple[1] };
      }
    } catch { return c.json({ error: 'invalid_cursor' }, 400); }
    try {
      const notes = sid ? await sessionStore.listNotes(sid, before) : undefined;
      if (!notes) return c.json({ error: 'not signed in' }, 401);
      const page = []; let bytes = 32;
      for (const note of notes) {
        const size = Buffer.byteLength(JSON.stringify(note), 'utf8') + 1;
        if (bytes + size > 48 * 1024) break;
        page.push(note); bytes += size;
      }
      const last = page.at(-1);
      const next = last && (page.length < notes.length || notes.length === 100)
        ? Buffer.from(JSON.stringify([last.createdAt, last.id])).toString('base64url') : undefined;
      return c.json({ notes: page, ...(next ? { next_cursor: next } : {}) });
    } catch { return unavailable(); }
  });

  // Live issuer checks precede the transaction; session authorization and the business write commit together.
  app.post('/notes', async (c) => {
    if (!sameOrigin(c.req.raw)) return c.json({ error: 'invalid_origin' }, 403);
    const sid = sessionCookie(c.req.raw);
    let s;
    try { s = sid ? await sessionStore.get(sid) : undefined; }
    catch { return unavailable(); }
    if (!s || !sid) return c.json({ error: 'not signed in' }, 401);
    const endSession = async (code: 'revoked' | 'reauthentication_required') => {
      try { await sessionStore.revoke(sid); } catch { return unavailable(); }
      // A newer sign-in may already have replaced this cookie while UserInfo was in flight. Revoke only the
      // session used by this request; an automatic failure must not erase the browser's newer session cookie.
      return c.json({ error: code }, 401);
    };
    if (!/^application\/json(?:\s*;|$)/i.test(c.req.header('content-type') ?? '')) return c.json({ error: 'expected_json' }, 415);
    let input: { id: string; text: string };
    try {
      // Bound streamed bodies as well as Content-Length. Never trust the claimed length alone.
      const reader = c.req.raw.body?.getReader();
      if (!reader) return c.json({ error: 'invalid_note' }, 400);
      const chunks: Uint8Array[] = []; let length = 0;
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => {}); }, 10_000);
      try {
        for (;;) {
          const part = await reader.read(); if (part.done) break;
          length += part.value.byteLength;
          if (length > 32 * 1024) { await reader.cancel(); return c.json({ error: 'body_too_large' }, 413); }
          chunks.push(part.value);
        }
      } finally { clearTimeout(timer); reader.releaseLock(); }
      if (timedOut) return c.json({ error: 'body_timeout' }, 408);
      input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some((key) => !['id', 'text'].includes(key))) throw new Error('invalid note');
      validateNote(input.id, input.text);
    } catch { return c.json({ error: 'invalid_note' }, 400); }
    try {
      if (!s.live) throw new RelyingPartyError('reauthentication_required', 'sign in again to do this');
      await rp.recheck(s.live); // Network work never holds a database transaction open.
    } catch (e) {
      if (e instanceof RelyingPartyError && (e.code === 'revoked' || e.code === 'reauthentication_required')) return endSession(e.code);
      return c.json({ error: 'recheck_failed' }, 503); // An unavailable Issuer is not evidence of revocation.
    }
    // A different host may have logged this session out while UserInfo was in flight.
    try { s = await sessionStore.get(sid); } catch { return unavailable(); }
    if (!s) return c.json({ error: 'not signed in' }, 401);
    if (!s.live) return endSession('reauthentication_required');
    try {
      const note = await sessionStore.saveNote(sid, input.id, input.text);
      return c.json({ saved: true, note });
    } catch (error) {
      if (error instanceof NoteError) {
        if (error.code === 'session_expired') return c.json({ error: 'not signed in' }, 401);
        if (error.code === 'reauthentication_required') return endSession(error.code);
        return c.json({ error: error.code }, 409);
      }
      return unavailable();
    }
  });

  app.post('/logout', async (c) => {
    if (!sameOrigin(c.req.raw)) return c.json({ error: 'invalid_origin' }, 403);
    const sid = sessionCookie(c.req.raw);
    try { if (sid) await sessionStore.revoke(sid); }
    catch { return unavailable(); }
    c.header('set-cookie', cookie('', 0));
    return c.json({ signed_out: true });
  });

  return { app, rp, sessionStore, sweep };
}
