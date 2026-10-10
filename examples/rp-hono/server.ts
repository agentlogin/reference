// A minimal application that accepts sign-ins from software agents with @agentlogin/rp.
//
//   ISSUER          Issuer to accept (default http://localhost:3000, the reference issuer in development mode)
//   BASE_URL        this application's public URL (default http://localhost:4000)
//   HANDLE_DOMAINS  for local development: handle domains served by ISSUER, mapped without WebFinger
//   STATE_SECRET    at least 32 characters (a development default is used when absent)
import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { serve } from '@hono/node-server';
import { randomBytes } from 'node:crypto';
import { RelyingParty, RelyingPartyError, createHandlers, signInForm, signInFormCss, type AgentIdentity, type LiveCheck } from '@agentlogin/rp';

const BASE = (process.env.BASE_URL ?? 'http://localhost:4000').replace(/\/$/, '');
const ISSUER = process.env.ISSUER ?? 'http://localhost:3000'; // exactly as the Issuer publishes it
const dev = BASE.startsWith('http://');
if (!dev && !process.env.STATE_SECRET) throw new Error('STATE_SECRET is required outside development');
const staticIssuers = Object.fromEntries((process.env.HANDLE_DOMAINS ?? (dev ? 'example.com' : '')).split(',').filter(Boolean).map((d) => [d.trim(), ISSUER]));

const rp = new RelyingParty({
  clientId: `${BASE}/client-metadata.json`, // an Open Client: this URL is the client identifier
  redirectUri: `${BASE}/auth/agent/callback`,
  issuers: [ISSUER],
  staticIssuers,
  stateSecret: process.env.STATE_SECRET ?? 'development-only-secret-development-only', // the fallback is reachable only over http on localhost
  allowInsecure: dev,
});

// Your own stores. Accounts are keyed on agent.key, which is (iss, sub): never on the handle. A session keeps the
// agent and, only for as long as the Access Token lives, what the live check needs. Owner data, when you request
// it, belongs in a store of its own (signIn.owner).
interface Session { agent: AgentIdentity; live?: LiveCheck }
const sessions = new Map<string, Session>();
const accounts = new Map<string, { firstSeen: string; handle?: string; ownerKey?: string }>();
const liveOf = (s: Session): LiveCheck | undefined => {
  if (s.live && s.live.accessTokenExpiresAt <= Date.now() / 1000) s.live = undefined; // Section 9 item 5: not kept past its lifetime
  return s.live;
};

const auth = createHandlers(rp, {
  metadata: { clientName: 'Agent Login example', initiateLoginUri: `${BASE}/auth/agent/login`, maxSignupsPerOwner: 3 },
  onSignIn: (signIn) => {
    if (!accounts.has(signIn.agent.key)) accounts.set(signIn.agent.key, { firstSeen: new Date().toISOString(), handle: signIn.agent.handle, ownerKey: signIn.agent.ownerKey });
    const sid = randomBytes(24).toString('base64url');
    sessions.set(sid, { agent: signIn.agent, live: rp.liveCheckOf(signIn) });
    return new Response(null, { status: 302, headers: { location: signIn.returnTo ?? '/me', 'set-cookie': `sid=${sid}; Path=/; HttpOnly; SameSite=Lax${dev ? '' : '; Secure'}; Max-Age=3600` } });
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
<p>This application accepts sign-ins from software agents. Enter your agent's handle, or point your agent at <code>${BASE}/auth/agent/login</code>.</p>
${signInForm({ action: '/auth/agent/login' })}`),
);

app.get('/me', (c) => {
  const s = sessions.get(getCookie(c, 'sid') ?? '');
  if (!s) return c.json({ error: 'not signed in' }, 401);
  return c.json({ account: s.agent.key, handle: s.agent.handle, name: s.agent.name, owner: s.agent.ownerKey, first_seen: accounts.get(s.agent.key)?.firstSeen });
});

// An action with lasting effect: re-check the agent at the Issuer first (Section 9 item 6).
app.post('/notes', async (c) => {
  const sid = getCookie(c, 'sid') ?? '';
  const s = sessions.get(sid);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  try {
    const live = liveOf(s);
    if (!live) throw new RelyingPartyError('reauthentication_required', 'sign in again to do this');
    await rp.recheck(live);
  } catch (e) {
    sessions.delete(sid);
    deleteCookie(c, 'sid');
    return c.json({ error: e instanceof RelyingPartyError ? e.code : 'recheck_failed' }, 401);
  }
  return c.json({ saved: true, by: s.agent.handle });
});

app.post('/logout', (c) => {
  sessions.delete(getCookie(c, 'sid') ?? '');
  setCookie(c, 'sid', '', { path: '/', maxAge: 0 });
  return c.json({ signed_out: true });
});

const port = Number(new URL(BASE).port || 4000);
serve({ fetch: app.fetch, port }, () => console.log(`Example application at ${BASE}, accepting agents from ${ISSUER}`));
