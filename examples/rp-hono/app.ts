// A minimal application that accepts sign-ins from software agents with @agentlogin/rp.
import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { randomBytes } from 'node:crypto';
import { RelyingParty, RelyingPartyError, createHandlers, signInForm, signInFormCss, type AgentIdentity, type LiveCheck } from '@agentlogin/rp';

export interface ExampleOptions {
  /** This application's public URL. */
  base: string;
  /** Issuer to accept, exactly as the Issuer publishes it. */
  issuer: string;
  stateSecret: string;
  /** For local development: handle domains served by `issuer`, mapped without WebFinger. */
  handleDomains?: string[];
  now?: () => number;
}
/**
 * A session lives on the server and ends on the server: the cookie's Max-Age is only a hint to the browser. It keeps
 * the agent and, only for as long as the Access Token lives, what the live check needs.
 */
export interface Session { agent: AgentIdentity; expiresAt: number; live?: LiveCheck }

export const SESSION_TTL = 3600; // seconds

export function createExample(o: ExampleOptions) {
  const base = o.base.replace(/\/$/, '');
  const dev = base.startsWith('http://');
  const now = o.now ?? (() => Math.floor(Date.now() / 1000));
  const rp = new RelyingParty({
    clientId: `${base}/client-metadata.json`, // an Open Client: this URL is the client identifier
    redirectUri: `${base}/auth/agent/callback`,
    issuers: [o.issuer],
    staticIssuers: Object.fromEntries((o.handleDomains ?? []).map((d) => [d, o.issuer])),
    stateSecret: o.stateSecret,
    allowInsecure: dev,
  });

  // Your own stores. Accounts are keyed on agent.key, which is (iss, sub): never on the handle. Owner data, when you
  // request it, belongs in a store of its own (signIn.owner).
  const sessions = new Map<string, Session>();
  const accounts = new Map<string, { firstSeen: string; handle?: string; ownerKey?: string }>();

  /** The session for a cookie value, or nothing once it has expired. Expired credentials are dropped on the way. */
  function sessionOf(sid: string | undefined): Session | undefined {
    const s = sid ? sessions.get(sid) : undefined;
    if (!s) return undefined;
    if (s.expiresAt <= now()) {
      sessions.delete(sid!);
      return undefined;
    }
    if (s.live && s.live.accessTokenExpiresAt <= now()) s.live = undefined; // Section 9 item 5: not kept past its lifetime
    return s;
  }
  /** Removes expired sessions and expired Access Tokens whether or not anyone asks for them. Run it periodically. */
  function sweep(): void {
    for (const [sid, s] of sessions) {
      if (s.expiresAt <= now()) sessions.delete(sid);
      else if (s.live && s.live.accessTokenExpiresAt <= now()) s.live = undefined;
    }
  }

  const auth = createHandlers(rp, {
    metadata: { clientName: 'Agent Login example', initiateLoginUri: `${base}/auth/agent/login`, maxSignupsPerOwner: 3 },
    onSignIn: (signIn) => {
      if (!accounts.has(signIn.agent.key)) accounts.set(signIn.agent.key, { firstSeen: new Date(now() * 1000).toISOString(), handle: signIn.agent.handle, ownerKey: signIn.agent.ownerKey });
      const sid = randomBytes(24).toString('base64url');
      sessions.set(sid, { agent: signIn.agent, expiresAt: now() + SESSION_TTL, live: rp.liveCheckOf(signIn) });
      return new Response(null, { status: 302, headers: { location: signIn.returnTo ?? '/me', 'set-cookie': `sid=${sid}; Path=/; HttpOnly; SameSite=Lax${dev ? '' : '; Secure'}; Max-Age=${SESSION_TTL}` } });
    },
  });

  const app = new Hono();
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

  app.get('/me', (c) => {
    const s = sessionOf(getCookie(c, 'sid'));
    if (!s) return c.json({ error: 'not signed in' }, 401);
    return c.json({ account: s.agent.key, handle: s.agent.handle, name: s.agent.name, owner: s.agent.ownerKey, first_seen: accounts.get(s.agent.key)?.firstSeen });
  });

  // An action with lasting effect: re-check the agent at the Issuer first (Section 9 item 6).
  app.post('/notes', async (c) => {
    const sid = getCookie(c, 'sid');
    const s = sessionOf(sid);
    if (!s) return c.json({ error: 'not signed in' }, 401);
    try {
      if (!s.live) throw new RelyingPartyError('reauthentication_required', 'sign in again to do this');
      await rp.recheck(s.live);
    } catch (e) {
      sessions.delete(sid!);
      setCookie(c, 'sid', '', { path: '/', maxAge: 0 });
      return c.json({ error: e instanceof RelyingPartyError ? e.code : 'recheck_failed' }, 401);
    }
    return c.json({ saved: true, by: s.agent.handle });
  });

  app.post('/logout', (c) => {
    sessions.delete(getCookie(c, 'sid') ?? '');
    setCookie(c, 'sid', '', { path: '/', maxAge: 0 });
    return c.json({ signed_out: true });
  });

  return { app, rp, sessions, sweep };
}
