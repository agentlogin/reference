// A minimal application that accepts sign-ins from software agents with @agentlogin/rp.
import { Hono } from 'hono';
import { randomBytes } from 'node:crypto';
import { RelyingParty, RelyingPartyError, createHandlers, signInForm, signInFormCss, type CallbackStateStore } from '@agentlogin/rp';
import { validSid, type SessionStore } from './session-store.js';
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
    metadata: { clientName: 'Agent Login example', initiateLoginUri: `${base}/auth/agent/login`, maxSignupsPerOwner: 3 },
    onSignIn: async (signIn, request) => {
      const sid = randomBytes(32).toString('base64url');
      try {
        // Commit the account, new session and old-cookie invalidation together before issuing the cookie.
        await sessionStore.create(sid, { agent: signIn.agent, expiresAt: now() + SESSION_TTL, live: rp.liveCheckOf(signIn) }, sessionCookie(request));
      } catch {
        return unavailable(); // Includes uncertain commits: start a new sign-in, never replay this callback.
      }
      return new Response(null, { status: 302, headers: {
        location: signIn.returnTo ?? '/me', 'set-cookie': cookie(sid, SESSION_TTL), 'cache-control': 'no-store, private',
      } });
    },
  });

  const app = new Hono();
  app.use('*', async (c, next) => {
    await next();
    if (['/me', '/notes', '/logout'].includes(c.req.path) || c.req.path.startsWith('/auth/agent/')) c.header('cache-control', 'no-store, private');
  });
  app.get('/client-metadata.json', (c) => auth.metadata(c.req.raw));
  app.all('/auth/agent/login', (c) => auth.login(c.req.raw));
  app.get('/auth/agent/callback', (c) => auth.callback(c.req.raw));

  app.get('/', (c) =>
    c.html(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent Login example</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}code{font-size:.9em}${signInFormCss}</style>
<h1>Agent Login example</h1>
<p>This application accepts sign-ins from software agents. Enter your agent's handle, or point your agent at <code>${base}/auth/agent/login</code>.</p>
${signInForm({ action: '/auth/agent/login' })}`),
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
      return c.json({ account: s.agent.key, handle: s.agent.handle, name: s.agent.name, owner: s.agent.ownerKey, first_seen: s.firstSeen });
    } catch { return unavailable(); }
  });

  // Demonstrates the live check required before a lasting action (Section 9 item 6); no note is persisted here.
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
    return c.json({ saved: true, by: s.agent.handle });
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
