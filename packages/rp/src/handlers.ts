// Handlers that take and return the web-standard Request and Response, so they plug into Hono, Next.js route
// handlers on the Node.js runtime, or Node's http module through any fetch adapter. The kit itself needs Node.js
// (node:crypto, and node:dns and node:http for the address-filtering fetch); it does not run on edge runtimes.
import { RelyingPartyError } from './errors.js';
import { createHmac } from 'node:crypto';
import type { CallbackStateStore } from './callback-store.js';
import type { ClientMetadataInput, RelyingParty, SignIn } from './rp.js';
import { seal, unseal } from './seal.js';

export interface HandlerOptions {
  /** Shared by all replicas/handler instances. Atomic one-use records must survive restarts; memory is for development. */
  callbackStore: CallbackStateStore;
  /**
   * Called after a validated sign-in. Create your own session here and return the response (usually a redirect).
   * Whatever it throws propagates to your framework unchanged.
   */
  onSignIn: (signIn: SignIn, request: Request) => Response | Promise<Response>;
  /** Render a failed sign-in. Default: a small HTML page; `access_denied` and `signup_limit_reached` read differently. */
  onError?: (error: RelyingPartyError, request: Request) => Response | Promise<Response>;
  /** Members of the Client ID Metadata Document served by `metadata` (Open Clients). */
  metadata?: ClientMetadataInput;
  /**
   * Seconds a started sign-in stays valid, 60 to 86400, default 900. A sign-in that waits for the agent's owner can
   * take longer than the default (up to T_OWNER, a day); when the window closes the callback answers `invalid_state`
   * and the sign-in has to be started again.
   */
  pendingTtlSeconds?: number;
  /** Receives every failure, for logging. Default: `console.warn` of the code and message for upstream and configuration failures. Never contains tokens. */
  log?: (error: RelyingPartyError) => void;
}
export interface Handlers {
  /** Starts a sign-in. Accepts `handle` (a form field or query parameter), or `iss` and `login_hint` (Section 5.8), by GET or POST. */
  login: (request: Request) => Promise<Response>;
  /** The `redirect_uri`. */
  callback: (request: Request) => Promise<Response>;
  /** The Client ID Metadata Document (Section 4.2). Serve it at the `client_id` URL. */
  metadata: (request: Request) => Response;
}

const MAX_PENDING = 5; // started sign-ins kept per browser
const MAX_FORM = 8 * 1024;
const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/**
 * A same-origin path only. Browsers strip tabs and newlines from URLs and treat a backslash as a slash, so anything
 * but printable characters without a backslash is refused, and the result must still resolve to the same origin.
 */
export function safeReturnTo(v: string | undefined | null): string | undefined {
  if (!v || v.length > 512 || !/^\/[\x21-\x5b\x5d-\x7e]*$/.test(v) || v.startsWith('//')) return undefined;
  try {
    const base = 'https://return.invalid';
    const u = new URL(v, base);
    return u.origin === base ? v : undefined;
  } catch {
    return undefined;
  }
}

function readCookies(request: Request): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}
async function readForm(request: Request): Promise<URLSearchParams> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_FORM) throw new RelyingPartyError('invalid_request', 'form too large');
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_FORM) {
        await reader.cancel();
        throw new RelyingPartyError('invalid_request', 'form too large');
      }
      chunks.push(value);
    }
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

export function createHandlers(rp: RelyingParty, o: HandlerOptions): Handlers {
  if (!o.callbackStore) throw new Error('callbackStore is required: share a durable store across all application replicas');
  const secure = rp.options.redirectUri.startsWith('https:');
  // `__Host-` binds the cookie to this exact host: a sibling subdomain or a plain-http attacker cannot plant one.
  const prefix = secure ? '__Host-al_' : 'al_';
  const cookieAttrs = `Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
  const cookieName = (state: string) => `${prefix}${state.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64)}`;
  const clear = (name: string) => `${name}=; ${cookieAttrs}; Max-Age=0`;
  const ttl = Math.min(86_400, Math.max(60, Math.floor(o.pendingTtlSeconds ?? 900)));
  const log = o.log ?? ((e: RelyingPartyError) => { if (e.status >= 500) console.warn(`agentlogin: ${e.code}: ${e.message}`); });
  const stateKey = (state: string) => createHmac('sha256', rp.options.stateSecret)
    .update(JSON.stringify([rp.options.clientId, rp.options.redirectUri, state])).digest('hex');
  const storageFailure = (cause?: unknown) => new RelyingPartyError('state_store_failed', 'sign-in state storage is unavailable', undefined, { cause });

  const fail = async (e: RelyingPartyError, request: Request, clearName?: string): Promise<Response> => {
    log(e);
    const res = o.onError ? await o.onError(e, request) : errorPage(e);
    return clearName ? withCookies(res, [clear(clearName)]) : res;
  };

  return {
    async login(request) {
      const q = new URLSearchParams(new URL(request.url).search);
      let initiated = false;
      try {
        if (request.method === 'POST') {
          if ((request.headers.get('content-type') ?? '').includes('application/x-www-form-urlencoded')) for (const [k, v] of await readForm(request)) q.append(k, v);
        } else if (request.method !== 'GET') {
          return new Response('method not allowed', { status: 405, headers: { allow: 'GET, POST' } });
        }
        const returnTo = safeReturnTo(q.get('return_to'));
        const iss = q.get('iss');
        initiated = iss !== null;
        // Section 5.8: `target_link_uri` is ignored; `iss` must be an accepted Issuer, and nothing is sent to any other.
        const begun = iss
          ? await rp.beginInitiated({ iss, loginHint: q.get('login_hint') ?? undefined, returnTo })
          : await rp.begin({ handle: q.get('handle') ?? q.get('login_hint') ?? undefined, issuer: q.get('issuer') ?? undefined, returnTo });
        const sealed = await seal(rp.options.stateSecret, begun.pending, ttl);
        try {
          if (!await o.callbackStore.register(stateKey(begun.pending.state), Date.now() + ttl * 1000)) throw storageFailure();
        } catch (e) {
          throw storageFailure(e);
        }
        // Keep the number of started sign-ins per browser small: drop the oldest ones this request carried.
        const existing = [...readCookies(request).keys()].filter((n) => n.startsWith(prefix));
        const cookies = existing.slice(0, Math.max(0, existing.length - (MAX_PENDING - 1))).map(clear);
        cookies.push(`${cookieName(begun.pending.state)}=${sealed}; ${cookieAttrs}; Max-Age=${ttl}`);
        return withCookies(new Response(null, { status: 302, headers: { location: begun.url, 'cache-control': 'no-store' } }), cookies);
      } catch (e) {
        if (!(e instanceof RelyingPartyError)) throw e;
        // Section 5.8: an `iss` that is not accepted is refused with 400, whatever the application's error page does.
        if (initiated && e.code === 'issuer_not_accepted') {
          log(e);
          return errorPage(e);
        }
        return fail(e, request);
      }
    },

    async callback(request) {
      const url = new URL(request.url);
      const state = url.searchParams.get('state') ?? '';
      const name = cookieName(state);
      let signIn: SignIn;
      try {
        const cookie = state ? readCookies(request).get(name) : undefined;
        const pending = cookie ? await unseal(rp.options.stateSecret, cookie) : null;
        // Claim before any token exchange. A process crash, uncertain exchange or onSignIn failure must never
        // release it: retrying a code can revoke the successful request's Access Token at the Issuer.
        if (pending && state === pending.state) {
          let claim;
          try { claim = await o.callbackStore.claim(stateKey(pending.state)); }
          catch (e) { throw storageFailure(e); }
          if (claim === 'duplicate') throw new RelyingPartyError('duplicate_callback', 'this sign-in was already completed');
          if (claim !== 'claimed') throw new RelyingPartyError('invalid_state', 'this sign-in was not started in this session, or it expired');
        }
        signIn = await rp.complete({ params: url.searchParams, pending });
      } catch (e) {
        if (!(e instanceof RelyingPartyError)) throw e;
        return fail(e, request, state ? name : undefined);
      }
      const res = await o.onSignIn(signIn, request); // the application's own failures are not the kit's to catch
      return withCookies(res, [clear(name)]);
    },

    metadata() {
      return new Response(JSON.stringify(rp.clientMetadata(o.metadata)), { headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' } });
    },
  };
}

function withCookies(res: Response, cookies: string[]): Response {
  const headers = new Headers(res.headers);
  for (const c of cookies) headers.append('set-cookie', c);
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/** Section 9 item 7: `access_denied` and `signup_limit_reached` are distinct outcomes. The text contains nothing from the Issuer. */
export function errorMessage(e: RelyingPartyError): string {
  switch (e.code) {
    case 'access_denied':
      return e.description === 'owner_declined'
        ? "The agent's owner declined this sign-in."
        : e.description === 'transaction_expired'
          ? 'The sign-in expired before it was completed. Start again.'
          : 'The sign-in was cancelled or is not permitted for this agent.';
    case 'signup_limit_reached':
      return "This application has reached the number of agents it accepts from this agent's owner.";
    case 'consent_required':
    case 'interaction_required':
      return 'The agent or its owner has to approve this sign-in first. Start again and complete the approval.';
    case 'invalid_state':
      return 'This sign-in was not started in this browser or it expired. Start again.';
    case 'duplicate_callback':
      return 'This sign-in was already completed.';
    case 'issuer_not_accepted':
      return 'This application does not accept agents from that provider.';
    case 'invalid_handle':
    case 'handle_required':
      return "Enter your agent's handle, for example scout@example.com.";
    case 'discovery_failed':
    case 'token_request_failed':
    case 'userinfo_failed':
      return "The agent's provider could not be reached. Try again shortly.";
    case 'configuration_error':
    case 'state_store_failed':
      return 'Sign-in is not available right now.';
    default:
      return 'The sign-in could not be completed.';
  }
}
/** The default error response: status by kind of failure (400, 500 or 502), text from `errorMessage`. */
export function errorPage(e: RelyingPartyError): Response {
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in not completed</title><body style="font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Sign-in not completed</h1><p>${escapeHtml(errorMessage(e))}</p><p style="color:#666;font-size:.85em">${escapeHtml(e.code)}</p></body>`;
  return new Response(html, { status: e.status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
