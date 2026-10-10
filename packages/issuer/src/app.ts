// HTTP surface of the issuer. Section numbers refer to Agent Login Core 1.0 draft 0.1.
import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie } from 'hono/cookie';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AGENT_KEY_ALGS, OWNER_SCOPES, SCOPES, VERSION } from './constants.js';
import type { IssuerContext } from './context.js';
import { OAuthError } from './errors.js';
import { redirectUriMatches, registerClient, resolveClient, type ClientContext } from './clients.js';
import type { Client, OwnerVerifiedVia, SessionAuth, Transaction } from './store.js';
import * as tx from './transactions.js';
import { authenticateClient, exchangeCode, userinfo } from './tokens.js';
import * as agents from './agents.js';
import { domainServed, isPlainObject, parseBearer, parseHandle, prefersJson, randomId, randomSecret, safeEqual, sha256 } from './util.js';

const WAIT_JS = readFileSync(fileURLToPath(new URL('../static/wait.js', import.meta.url)), 'utf8');
const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };
/** Section 5.3: only the Issuer's own scripts, never framed. */
const HTML_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src https:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

/** Lifetime of the one-time code of the Owner email sign-in, seconds. */
const OWNER_CODE_TTL = 600;

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
/** Section 5.3: JSON embedded in HTML with <, >, &, U+2028 and U+2029 escaped. */
const embedJson = (v: unknown) => JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);

export function createIssuerApp(ctx: IssuerContext): Hono {
  const app = new Hono();
  const clientCtx: ClientContext = { store: ctx.store, constants: ctx.constants, allowInsecureClients: ctx.allowInsecureClients };
  const base = ctx.issuer;
  const secureCookies = base.startsWith('https:');

  // Section 5: every response of Sections 5 to 7, redirects and CORS preflights included, carries Cache-Control: no-store.
  const noStore = async (c: Context, next: () => Promise<void>) => {
    await next();
    if (!c.res.headers.has('Cache-Control')) c.res.headers.set('Cache-Control', 'no-store');
  };
  for (const path of ['/authorize', '/transactions/*', '/token', '/userinfo', '/register', '/agents/*', '/owner/*']) app.use(path, noStore);
  // Section 6: CORS for browser-based Agent Clients, never with Access-Control-Allow-Credentials.
  app.use('/transactions/*', cors({ origin: '*', allowHeaders: ['Authorization', 'Content-Type', 'Accept'], allowMethods: ['GET', 'POST', 'OPTIONS'] }));
  app.use('/agents/*', cors({ origin: '*', allowHeaders: ['Authorization', 'Content-Type', 'Accept'], allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'] }));

  app.onError((err, c) => {
    if (err instanceof OAuthError) {
      const body: Record<string, unknown> = { error: err.error };
      if (err.description) body.error_description = err.description;
      const extra = (c.get as unknown as (k: string) => unknown)('txError') as Record<string, unknown> | undefined;
      return c.json({ ...body, ...extra }, err.status as 400, { ...NO_STORE, ...err.headers });
    }
    console.error(err);
    return c.json({ error: 'server_error' }, 500, NO_STORE);
  });

  // ---- Section 2.4, 7.7: discovery and keys -----------------------------------------------------
  app.get('/.well-known/openid-configuration', (c) =>
    c.json(
      {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        userinfo_endpoint: `${base}/userinfo`,
        jwks_uri: `${base}/.well-known/jwks.json`,
        registration_endpoint: `${base}/register`,
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
        id_token_signing_alg_values_supported: ['ES256'],
        agent_key_algs_supported: [...AGENT_KEY_ALGS],
        subject_types_supported: ['public'],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        scopes_supported: [...SCOPES],
        claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nonce', 'actor_type', 'scope', 'email', 'email_verified', 'name', 'preferred_username', 'owner_sub', 'owner_name', 'owner_email', 'owner_email_verified', 'owner_verified_via'],
        token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
        transaction_endpoint: `${base}/transactions`,
        agents_endpoint: `${base}/agents`,
        handle_domains: ctx.handleDomains,
        agent_login_versions_supported: [VERSION],
        service_documentation: 'https://github.com/agentlogin/spec',
      },
      200,
      { 'Cache-Control': 'public, max-age=3600' },
    ),
  );
  app.get('/.well-known/jwks.json', (c) =>
    c.json({ keys: [{ ...ctx.signingKey.publicJwk, kid: ctx.signingKey.kid, use: 'sig', alg: 'ES256' }] }, 200, { 'Cache-Control': 'public, max-age=3600' }),
  );
  // Section 2.2: WebFinger for handles in the served domains (per-handle lookups only).
  app.get('/.well-known/webfinger', async (c) => {
    const resource = c.req.query('resource') ?? '';
    const h = resource.startsWith('acct:') ? parseHandle(resource.slice(5)) : null;
    if (!h || !domainServed(h.domain, ctx.handleDomains) || !(await ctx.store.getAgent(h.handle))) return c.body(null, 404);
    const rel = c.req.queries('rel') ?? [];
    const links = [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: base }].filter((l) => rel.length === 0 || rel.includes(l.rel));
    return c.json({ subject: `acct:${h.handle}`, links }, 200, { 'Content-Type': 'application/jrd+json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=3600' });
  });

  // ---- Section 5: Authentication Request ---------------------------------------------------------
  const authorize = async (c: Context) => {
    const q: Record<string, string[]> = { ...c.req.queries() };
    if (c.req.method === 'POST') {
      const form = await c.req.parseBody({ all: true });
      for (const [k, v] of Object.entries(form)) q[k] = [...(q[k] ?? []), ...(Array.isArray(v) ? v.map(String) : [String(v)])];
    }
    const json = prefersJson(c.req.header('accept'));
    const one = (k: string): string | undefined => {
      const v = q[k];
      if (!v) return undefined;
      if (v.length > 1) throw new OAuthError(400, 'invalid_request', `repeated parameter ${k}`);
      return v[0];
    };
    // Section 5.2 steps 1 and 2: a failure here is answered 400 directly, never by redirect; as HTML unless JSON is preferred.
    const direct = (text: string) => c.html(page('Sign-in request rejected', `<p>${escapeHtml(text)}</p>`), 400, { ...NO_STORE, ...HTML_HEADERS });
    let client: Client;
    let redirectUri: string;
    try {
      const clientId = one('client_id');
      redirectUri = one('redirect_uri') ?? '';
      if (!clientId || !redirectUri) throw new OAuthError(400, 'invalid_request', 'client_id and redirect_uri are required');
      client = await resolveClient(clientCtx, clientId);
    } catch (e) {
      // Step 1: every way the client fails to resolve, an Open Client document the Issuer refuses included (Sections 3.2, 4.2), is `invalid_request`.
      if (!(e instanceof OAuthError) || e.status !== 400) throw e;
      if (!json) return direct('The application could not be identified.');
      throw new OAuthError(400, 'invalid_request', e.description);
    }
    if (!redirectUriMatches(client, redirectUri)) {
      if (json) throw new OAuthError(400, 'invalid_request', 'redirect_uri does not match');
      return direct('The application sent a redirect address that it did not register.');
    }
    const redirectError = (error: string, description: string, state?: string) => {
      const u = new URL(redirectUri);
      u.searchParams.set('error', error);
      u.searchParams.set('error_description', description);
      if (state) u.searchParams.set('state', state);
      u.searchParams.set('iss', base);
      if (json) return c.json({ error, error_description: description, redirect: u.href }, 400, NO_STORE);
      c.header('Cache-Control', 'no-store');
      return c.redirect(u.href, 303);
    };
    let state: string | undefined;
    try {
      state = one('state');
      const nonce = one('nonce');
      const codeChallenge = one('code_challenge');
      const method = one('code_challenge_method');
      const responseType = one('response_type');
      const scopeRaw = one('scope') ?? '';
      const prompt = one('prompt');
      const loginHintRaw = one('login_hint');
      const responseMode = one('response_mode');
      for (const k of ['max_age', 'claims', 'display', 'ui_locales', 'id_token_hint', 'acr_values']) one(k); // ignored, but not repeatable
      if (one('request') !== undefined) return redirectError('request_not_supported', 'request objects are not supported', state);
      if (one('request_uri') !== undefined) return redirectError('request_uri_not_supported', 'request_uri is not supported', state);
      if (responseMode !== undefined && responseMode !== 'query') return redirectError('invalid_request', 'response_mode must be query', state);
      if (responseType !== 'code') return redirectError('unsupported_response_type', 'response_type must be code', state);
      if (!state || !nonce) return redirectError('invalid_request', 'state and nonce are required', state);
      if (!codeChallenge || method !== 'S256' || !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)) return redirectError('invalid_request', 'PKCE S256 is required', state);
      const scopes = tx.scopeList(scopeRaw);
      if (!scopes.includes('openid')) return redirectError('invalid_scope', 'openid is required', state);
      if (client.type === 'open' && scopes.some((s) => OWNER_SCOPES.includes(s))) return redirectError('invalid_scope', 'owner scopes require a registered client', state);
      if (scopes.includes('owner_email') && (!client.tosUri || !client.policyUri)) return redirectError('invalid_request', 'a client requesting owner_email must publish tos_uri and policy_uri', state);
      const promptValue = prompt?.split(' ').find((p) => p === 'consent' || p === 'none') as 'consent' | 'none' | undefined;
      let loginHint: string | undefined;
      if (loginHintRaw !== undefined) {
        const h = parseHandle(loginHintRaw);
        if (!h) return redirectError('invalid_request', 'login_hint is not a handle', state);
        loginHint = h.handle;
      }
      const sessionSecret = randomSecret();
      const ua = c.req.header('user-agent');
      const t = await tx.createTransaction(ctx, {
        client,
        redirectUri,
        scopes,
        state,
        nonce,
        codeChallenge,
        prompt: promptValue,
        loginHint,
        requester: ua ? { user_agent: ua.slice(0, 200) } : undefined,
        sessionSecret,
      });
      if (json) return c.json({ ...tx.resource(ctx, t, client, { kind: 'session' }), session_token: sessionSecret }, 200, NO_STORE);
      setCookie(c, 'als', sessionSecret, { path: `/transactions/${t.id}`, httpOnly: true, secure: secureCookies, sameSite: 'Lax', maxAge: ctx.constants.T_OWNER });
      c.header('Cache-Control', 'no-store');
      return c.redirect(`${base}/transactions/${t.id}/wait`, 303);
    } catch (e) {
      if (e instanceof OAuthError && e.status === 400) return redirectError(e.error, e.description ?? e.error, state);
      throw e;
    }
  };
  app.get('/authorize', authorize);
  app.post('/authorize', authorize);

  // ---- Section 6: the transaction -----------------------------------------------------------------
  /** Loads the transaction, its client and the viewer; stores status/next for error bodies. */
  async function loadTx(c: Context): Promise<{ t: Transaction; client: Client; viewer: tx.Viewer }> {
    const t = await tx.loadTransaction(ctx, c.req.param('id') ?? '');
    const client = (await ctx.store.getClient(t.clientId))!;
    let viewer: tx.Viewer;
    try {
      viewer = tx.identifyViewer(t, parseBearer(c.req.header('authorization')), getCookie(c, 'als') ?? null);
    } catch (e) {
      c.set('txError' as never, { status: t.status, next: tx.resource(ctx, t, client, { kind: 'none' }).next } as never);
      throw e;
    }
    c.set('txError' as never, { status: t.status, next: tx.resource(ctx, t, client, viewer).next } as never);
    return { t, client, viewer };
  }

  app.get('/transactions/:id', async (c) => {
    const { t, client, viewer } = await loadTx(c);
    return c.json(tx.resource(ctx, t, client, viewer), 200, { ...NO_STORE, Link: `<${tx.txUrl(ctx, t.id)}>; rel="agent-login-transaction"` });
  });

  app.get('/transactions/:id/wait', async (c) => {
    const { t, client, viewer } = await loadTx(c);
    const r = tx.resource(ctx, t, client, viewer);
    const name = escapeHtml(client.clientName ?? new URL(t.redirectUri).host);
    const html = page(
      'Sign in with your agent',
      `<p>Signing in to <strong>${name}</strong>.</p><p id="status">Waiting for your agent to sign in.</p>` +
        `<p class="muted">Transaction <code id="txid"></code></p>` +
        `<script type="application/json" id="agent-login-transaction">${embedJson(r)}</script><script src="${base}/static/wait.js"></script>`,
    );
    return c.html(html, 200, { ...NO_STORE, ...HTML_HEADERS, Link: `<${tx.txUrl(ctx, t.id)}>; rel="agent-login-transaction"` });
  });

  // Section 6.7 precedence: the transaction is loaded (`invalid_transaction`), the credential checked (`invalid_token`)
  // and a terminal status reported (`transaction_expired`) before a malformed body is; every error of an existing
  // transaction then carries `status` and `next`.
  app.post('/transactions/:id/assertion', async (c) => {
    const body = await deferredJsonBody(c);
    return ctx.locks.run(c.req.param('id') ?? '', async () => {
      const { t, client } = await loadTx(c);
      tx.requireOpen(t);
      const token = await tx.assert(ctx, t, client, body());
      return c.json({ ...tx.resource(ctx, t, client, { kind: 'transaction_token' }), transaction_token: token }, 200, NO_STORE);
    });
  });

  app.post('/transactions/:id/review', async (c) => {
    const body = await deferredJsonBody(c);
    return ctx.locks.run(c.req.param('id') ?? '', async () => {
      const { t, client, viewer } = await loadTx(c);
      tx.requireTransactionToken(viewer);
      tx.requireOpen(t);
      await tx.review(ctx, t, client, viewer, body());
      return c.json(tx.resource(ctx, t, client, viewer), 200, NO_STORE);
    });
  });

  app.get('/transactions/:id/continue/:secret', async (c) =>
    ctx.locks.run(c.req.param('id') ?? '', async () => {
      const { t, viewer } = await loadTx(c);
      const { redirect } = await tx.cont(ctx, t, c.req.param('secret') ?? '', viewer);
      if (prefersJson(c.req.header('accept'))) return c.json({ redirect }, 200, NO_STORE);
      c.header('Cache-Control', 'no-store');
      return c.redirect(redirect, 303);
    }),
  );

  // ---- Section 5.6, 3.3: tokens --------------------------------------------------------------------
  app.post('/token', async (c) => {
    const form = await c.req.parseBody();
    const str = (k: string) => (typeof form[k] === 'string' ? (form[k] as string) : undefined);
    const auth = c.req.header('authorization');
    let basic: { id: string; secret: string } | undefined;
    if (auth && /^Basic\s+/i.test(auth)) {
      const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i < 0) throw new OAuthError(401, 'invalid_client');
      basic = { id: decodeURIComponent(decoded.slice(0, i)), secret: decodeURIComponent(decoded.slice(i + 1)) };
    }
    const req = { grantType: str('grant_type'), code: str('code'), redirectUri: str('redirect_uri'), codeVerifier: str('code_verifier'), clientIdParam: str('client_id'), clientSecretParam: str('client_secret'), basic };
    if (basic && req.clientIdParam && basic.id !== req.clientIdParam) throw new OAuthError(400, 'invalid_request', 'client_id mismatch');
    const client = await authenticateClient(ctx, req);
    return c.json(await exchangeCode(ctx, client, req), 200, NO_STORE);
  });
  app.get('/userinfo', async (c) => c.json(await userinfo(ctx, parseBearer(c.req.header('authorization'))), 200, NO_STORE));
  app.post('/userinfo', async (c) => c.json(await userinfo(ctx, parseBearer(c.req.header('authorization'))), 200, NO_STORE));

  // ---- Section 4.3: registration (RFC 7591 with an initial access token) ---------------------------
  app.post('/register', async (c) => {
    requireAdmin(c);
    return c.json(await registerClient(clientCtx, await jsonBody(c)), 201, NO_STORE);
  });

  // ---- Section 7.2, 7.8: agent management ----------------------------------------------------------
  const handleOf = (c: Context) => {
    const h = parseHandle(decodeURIComponent(c.req.param('handle') ?? ''));
    if (!h) throw new OAuthError(404, 'not_found');
    return h.handle;
  };
  app.post('/agents/:handle/keys', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    const r = await agents.enrollKey(ctx, handle, await jsonBody(c));
    return c.json({ ...r.record, challenge: r.challenge, proof_url: r.proof_url }, 201, NO_STORE);
  });
  app.post('/agents/:handle/keys/:kid/proof', async (c) => c.json(await agents.proveKey(ctx, handleOf(c), decodeURIComponent(c.req.param('kid') ?? ''), await jsonBody(c)), 200, NO_STORE));
  app.get('/agents/:handle/keys', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    return c.json({ keys: (await agents.listLiveKeys(ctx, handle)).map((k) => agents.keyRecord(ctx, k)) }, 200, NO_STORE);
  });
  app.get('/agents/:handle/keys/:kid', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    const k = await agents.getLiveKey(ctx, decodeURIComponent(c.req.param('kid') ?? ''));
    if (!k || k.handle !== handle) throw new OAuthError(404, 'not_found');
    return c.json(agents.keyRecord(ctx, k), 200, NO_STORE);
  });
  app.patch('/agents/:handle/keys/:kid', async (c) => {
    const handle = handleOf(c);
    const body = await jsonBody(c);
    const wantsPermissions = isPlainObject(body) && body.permissions !== undefined;
    const cred = await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, !wantsPermissions);
    const k = await agents.getLiveKey(ctx, decodeURIComponent(c.req.param('kid') ?? ''));
    if (!k || k.handle !== handle) throw new OAuthError(404, 'not_found');
    if (!isPlainObject(body)) throw new OAuthError(400, 'invalid_request');
    if (wantsPermissions) {
      // Section 7.8: `share_owner` is granted only by an Owner Credential from a session that satisfies Section 6.6; nothing changes otherwise.
      if (!agents.approvalSession(cred)) throw new OAuthError(403, 'insufficient_permission', 'share_owner requires an Owner Credential from a session of Section 6.6', { 'WWW-Authenticate': 'Bearer error="insufficient_scope"' });
      if (!isPlainObject(body.permissions) || typeof body.permissions.share_owner !== 'boolean') throw new OAuthError(400, 'invalid_request', 'permissions.share_owner');
      k.permissions.share_owner = body.permissions.share_owner;
    }
    if (typeof body.name === 'string') k.name = body.name.slice(0, 200);
    await ctx.store.putKey(k);
    return c.json(agents.keyRecord(ctx, k), 200, NO_STORE);
  });
  app.delete('/agents/:handle/keys/:kid', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    const k = await agents.getLiveKey(ctx, decodeURIComponent(c.req.param('kid') ?? ''));
    if (!k || k.handle !== handle) throw new OAuthError(404, 'not_found');
    if (k.status !== 'revoked') await agents.revokeKeyEffects(ctx, k);
    return c.body(null, 204, NO_STORE);
  });
  app.delete('/agents/:handle/keys', async (c) => {
    const handle = handleOf(c);
    const cred = await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    await agents.revokeAllKeys(ctx, handle, cred);
    return c.body(null, 204, NO_STORE);
  });
  app.get('/agents/:handle/accounts', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    return c.json({ accounts: (await ctx.store.listAccounts(handle)).map(agents.accountRecord) }, 200, NO_STORE);
  });
  app.patch('/agents/:handle/accounts/:client_id', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    const body = await jsonBody(c);
    if (!isPlainObject(body) || (body.status !== 'enabled' && body.status !== 'disabled')) throw new OAuthError(400, 'invalid_request', 'status must be enabled or disabled');
    const cred = await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    if (cred.kind === 'delegated' && body.status === 'enabled') throw new OAuthError(403, 'insufficient_permission', 'a Delegated Credential may only disable', { 'WWW-Authenticate': 'Bearer error="insufficient_scope"' });
    return c.json(await agents.setAccountStatus(ctx, handle, decodeURIComponent(c.req.param('client_id') ?? ''), body.status), 200, NO_STORE);
  });
  app.delete('/agents/:handle/consents/:client_id', async (c) => {
    const handle = handleOf(c);
    await agents.authorizeManagement(ctx, c.req.header('authorization'), handle, true);
    await ctx.store.deleteConsent(handle, decodeURIComponent(c.req.param('client_id') ?? ''));
    return c.body(null, 204, NO_STORE);
  });

  // ---- Section 6.6: Owner approval (API form; an HTML page can be layered on it) --------------------
  async function ownerOf(c: Context) {
    const bearer = parseBearer(c.req.header('authorization'));
    const cred = bearer ? await ctx.store.getCredential(sha256(bearer)) : undefined;
    if (!cred || cred.kind !== 'owner') throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
    return cred;
  }
  app.get('/owner/transactions/:id', async (c) => {
    const cred = await ownerOf(c);
    const t = await tx.loadTransaction(ctx, c.req.param('id') ?? '');
    if (t.ownerId !== cred.ownerId) throw new OAuthError(404, 'invalid_transaction');
    const client = (await ctx.store.getClient(t.clientId))!;
    // Section 6.6: the approval view names the client with its redirect_host, the requested Owner Claims and the handle;
    // a client registered with relay_issuer is named as a Relay that forwards the Owner Claims under its op_policy_uri,
    // which Section 4.4 has the Issuer read from the Relay's metadata.
    return c.json(
      {
        transaction_id: t.id,
        status: t.status,
        handle: t.handle,
        client: { client_id: client.clientId, client_name: client.clientName, redirect_host: new URL(t.redirectUri).host, tos_uri: client.tosUri, policy_uri: client.policyUri, relay_issuer: client.relayIssuer },
        relay: client.relayIssuer
          ? { issuer: client.relayIssuer, op_policy_uri: client.relayPolicyUri, notice: `This client is a Relay. The Owner Claims will be forwarded to Relying Parties of that Relay under its policy at ${client.relayPolicyUri}.` }
          : undefined,
        requested_owner_claims: t.scopes.filter((s) => OWNER_SCOPES.includes(s)).flatMap((s) => (s === 'owner_profile' ? ['owner_name'] : ['owner_email'])),
        expires_at: t.expiresAt,
      },
      200,
      NO_STORE,
    );
  });
  app.post('/owner/transactions/:id/decision', async (c) => {
    const cred = await ownerOf(c);
    // Section 6.6: a session established by a one-time code or link alone cannot approve or refuse.
    if (!agents.approvalSession(cred)) throw new OAuthError(403, 'insufficient_permission', 'Owner approval requires a session of Section 6.6', { 'WWW-Authenticate': 'Bearer error="insufficient_scope"' });
    const t = await tx.loadTransaction(ctx, c.req.param('id') ?? '');
    const body = await jsonBody(c);
    await ctx.locks.run(t.id, () => tx.ownerDecision(ctx, t, cred.ownerId, isPlainObject(body) ? body.decision : undefined));
    return c.json({ transaction_id: t.id, status: t.status, reason: t.reason }, 200, NO_STORE);
  });

  // ---- Section 7.5 `email`: Owner sign-in by a one-time code ------------------------------------------
  // How an Owner authenticates is outside the wire protocol (Section 1.4). This is the method every Issuer supports;
  // the Owner Credential it issues comes from a session established by a one-time code alone, so under Sections 6.6
  // and 7.8 it manages the Owner's Agents but neither approves a transaction nor grants `share_owner`.
  app.post('/owner/sessions/email', async (c) => {
    const b = await jsonBody(c);
    if (!isPlainObject(b) || typeof b.email !== 'string') throw new OAuthError(400, 'invalid_request', 'email required');
    if (!ctx.sendOwnerCode) throw new OAuthError(501, 'not_supported', 'no delivery channel for one-time codes is configured');
    const owner = await ctx.store.getOwnerByEmail(b.email);
    if (owner) {
      const code = randomId();
      const expiresAt = ctx.now() + OWNER_CODE_TTL;
      await ctx.store.putOwnerCode({ ownerId: owner.id, hash: sha256(code), expiresAt }); // replaces an earlier code for this Owner
      await ctx.sendOwnerCode({ email: owner.email, code, expiresAt });
    }
    return c.json({ sent: true }, 202, NO_STORE); // the same answer whether or not the address belongs to an Owner
  });
  app.post('/owner/sessions/email/verify', async (c) => {
    const b = await jsonBody(c);
    if (!isPlainObject(b) || typeof b.email !== 'string' || typeof b.code !== 'string') throw new OAuthError(400, 'invalid_request', 'email and code required');
    const owner = await ctx.store.getOwnerByEmail(b.email);
    const pending = owner && (await ctx.store.takeOwnerCode(owner.id)); // single use: taken whether or not it matches
    if (!owner || !pending || ctx.now() >= pending.expiresAt || !safeEqual(sha256(b.code), pending.hash)) throw new OAuthError(401, 'invalid_token', 'the code is wrong, used or expired', { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
    const credential = randomSecret();
    await ctx.store.putCredential({ hash: sha256(credential), ownerId: owner.id, kind: 'owner', sessionAuth: 'email_only', createdAt: ctx.now() });
    return c.json({ owner_id: owner.id, credential, session_auth: 'email_only' }, 200, NO_STORE);
  });

  // ---- Bootstrap API (outside the specification): owners, agents, credentials -----------------------
  app.post('/admin/owners', async (c) => {
    requireAdmin(c);
    const b = await jsonBody(c);
    if (!isPlainObject(b) || typeof b.email !== 'string') throw new OAuthError(400, 'invalid_request', 'email required');
    const id = randomId();
    const via = b.verified_via;
    const sessionAuth = parseSessionAuth(b.session_auth);
    // Section 7.5: `owner_verified_via` reports the strongest method used, the one of the credential's session included.
    const verifiedVia = strongest(via === 'oidc' || via === 'domain' || via === 'passkey' ? via : 'email', methodOf(sessionAuth));
    await ctx.store.putOwner({ id, ownerSub: randomSecret(), email: b.email, emailVerified: true, name: typeof b.name === 'string' ? b.name : undefined, verifiedVia, createdAt: ctx.now() });
    const credential = randomSecret();
    await ctx.store.putCredential({ hash: sha256(credential), ownerId: id, kind: 'owner', sessionAuth, createdAt: ctx.now() });
    return c.json({ owner_id: id, credential, session_auth: sessionAuth, verified_via: verifiedVia }, 201, NO_STORE);
  });
  app.delete('/admin/agents/:handle', async (c) => {
    requireAdmin(c);
    const a = await ctx.store.getAgent(handleOf(c));
    if (!a) throw new OAuthError(404, 'not_found');
    await agents.deleteAgent(ctx, a);
    return c.body(null, 204, NO_STORE);
  });
  app.post('/admin/agents', async (c) => {
    requireAdmin(c);
    const b = await jsonBody(c);
    if (!isPlainObject(b) || typeof b.handle !== 'string' || typeof b.owner_id !== 'string') throw new OAuthError(400, 'invalid_request', 'handle and owner_id required');
    const h = parseHandle(b.handle);
    if (!h || !domainServed(h.domain, ctx.handleDomains)) throw new OAuthError(400, 'invalid_request', 'handle not in a served domain');
    if (!(await ctx.store.getOwner(b.owner_id))) throw new OAuthError(404, 'not_found', 'owner');
    if (await ctx.store.getAgent(h.handle)) throw new OAuthError(409, 'invalid_request', 'handle exists');
    await ctx.store.putAgent({ ...h, sub: randomSecret(), ownerId: b.owner_id, name: typeof b.name === 'string' ? b.name : undefined, preferredUsername: typeof b.preferred_username === 'string' ? b.preferred_username : h.local, enabled: true, createdAt: ctx.now() });
    return c.json({ handle: h.handle, owner_id: b.owner_id }, 201, NO_STORE);
  });
  app.patch('/admin/agents/:handle', async (c) => {
    requireAdmin(c);
    const handle = handleOf(c);
    const a = await ctx.store.getAgent(handle);
    const b = await jsonBody(c);
    if (!a || !isPlainObject(b) || typeof b.enabled !== 'boolean') throw new OAuthError(400, 'invalid_request');
    await agents.setAgentEnabled(ctx, a, b.enabled);
    return c.json({ handle, enabled: a.enabled }, 200, NO_STORE);
  });
  app.post('/admin/credentials', async (c) => {
    requireAdmin(c);
    const b = await jsonBody(c);
    if (!isPlainObject(b) || typeof b.owner_id !== 'string') throw new OAuthError(400, 'invalid_request', 'owner_id required');
    const kind = b.kind === 'delegated' ? 'delegated' : 'owner';
    const handle = typeof b.handle === 'string' ? parseHandle(b.handle)?.handle : undefined;
    if (kind === 'delegated' && !handle) throw new OAuthError(400, 'invalid_request', 'delegated credentials need a handle');
    const owner = await ctx.store.getOwner(b.owner_id);
    if (!owner) throw new OAuthError(404, 'not_found', 'owner');
    const credential = randomSecret();
    const sessionAuth = kind === 'owner' ? parseSessionAuth(b.session_auth) : undefined;
    if (sessionAuth && strongest(owner.verifiedVia, methodOf(sessionAuth)) !== owner.verifiedVia) {
      await ctx.store.putOwner({ ...owner, verifiedVia: methodOf(sessionAuth) }); // Section 7.5: the strongest method used
    }
    await ctx.store.putCredential({ hash: sha256(credential), ownerId: b.owner_id, kind, handle, sessionAuth, createdAt: ctx.now() });
    return c.json({ credential, kind, handle, session_auth: sessionAuth }, 201, NO_STORE);
  });

  app.get('/static/wait.js', (c) => c.body(WAIT_JS, 200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=3600' }));
  app.get('/', (c) => c.html(page('Agent Login issuer', `<p>This server is an Agent Login issuer for ${ctx.handleDomains.map(escapeHtml).join(', ')}.</p><p><a href="${base}/.well-known/openid-configuration">Metadata</a></p>`), 200, HTML_HEADERS));

  function requireAdmin(c: Context) {
    const b = parseBearer(c.req.header('authorization'));
    if (!b || !safeEqual(b, ctx.adminToken)) throw new OAuthError(401, 'invalid_token', undefined, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  }
  return app;
}

/**
 * Bootstrap `session_auth`: how the session that obtained an Owner Credential authenticated the Owner (Section 6.6).
 * It fails closed: a caller that does not state it gets `email_only`, which neither approves nor grants `share_owner`.
 */
function parseSessionAuth(v: unknown): SessionAuth {
  if (v === undefined) return 'email_only';
  if (v === 'passkey' || v === 'oidc' || v === 'domain' || v === 'email_factor' || v === 'email_only') return v;
  throw new OAuthError(400, 'invalid_request', 'session_auth must be passkey, oidc, domain, email_factor or email_only');
}
/** Section 7.5: the verification methods from weakest to strongest, and the one a session of each kind amounts to. */
const METHODS: OwnerVerifiedVia[] = ['email', 'oidc', 'domain', 'passkey'];
const methodOf = (s: SessionAuth): OwnerVerifiedVia => (s === 'email_only' || s === 'email_factor' ? 'email' : s);
const strongest = (a: OwnerVerifiedVia, b: OwnerVerifiedVia): OwnerVerifiedVia => (METHODS.indexOf(a) >= METHODS.indexOf(b) ? a : b);

async function jsonBody(c: Context): Promise<unknown> {
  const ct = (c.req.header('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (ct !== 'application/json') throw new OAuthError(400, 'invalid_request', 'Content-Type must be application/json');
  const text = await c.req.text();
  if (text.length > 64 * 1024) throw new OAuthError(400, 'invalid_request', 'body too large');
  try {
    return JSON.parse(text);
  } catch {
    throw new OAuthError(400, 'invalid_request', 'malformed JSON');
  }
}

/** Reads the body now and reports a malformed one only when it is used, so that the errors Section 6.7 ranks higher come first. */
async function deferredJsonBody(c: Context): Promise<() => unknown> {
  try {
    const v = await jsonBody(c);
    return () => v;
  } catch (e) {
    return () => {
      throw e;
    };
  }
}

/** Section 5.3: every HTML page carries a CSP that permits only the Issuer's own scripts and forbids framing. */
function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#222}.muted{color:#666;font-size:.9em}code{font-size:.9em}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

