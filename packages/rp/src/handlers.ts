// Web-standard (Request/Response) handlers: usable from Hono, Next.js route handlers, Cloudflare Workers, Bun,
// Deno, or Node's http module through any fetch adapter.
import { RelyingPartyError } from './errors.js';
import type { ClientMetadataInput, RelyingParty, SignIn } from './rp.js';
import { seal, unseal } from './seal.js';

const TTL = 900; // seconds a started sign-in stays valid; a transaction waiting for the Owner may run longer and must be restarted

export interface HandlerOptions {
  /** Called after a validated sign-in. Create your own session here and return the response (usually a redirect). */
  onSignIn: (signIn: SignIn, request: Request) => Response | Promise<Response>;
  /** Render a failed sign-in. Default: a small HTML page; `access_denied` and `signup_limit_reached` read differently. */
  onError?: (error: RelyingPartyError, request: Request) => Response | Promise<Response>;
  /** Members of the Client ID Metadata Document served by `metadata` (Open Clients). */
  metadata?: ClientMetadataInput;
}
export interface Handlers {
  /** Starts a sign-in. Accepts `handle` (a form field or query parameter), or `iss` and `login_hint` (Section 5.8), by GET or POST. */
  login: (request: Request) => Promise<Response>;
  /** The `redirect_uri`. */
  callback: (request: Request) => Promise<Response>;
  /** The Client ID Metadata Document (Section 4.2). Serve it at the `client_id` URL. */
  metadata: (request: Request) => Response;
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const cookieName = (state: string) => `al_${state.replace(/[^A-Za-z0-9_-]/g, '')}`;
/** A same-origin path only: no scheme, no host, no backslashes. */
const safeReturnTo = (v: string | undefined): string | undefined => (v && /^\/(?![/\\])[^\\]*$/.test(v) ? v : undefined);

function readCookie(request: Request, name: string): string | undefined {
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

export function createHandlers(rp: RelyingParty, o: HandlerOptions): Handlers {
  const secure = rp.options.redirectUri.startsWith('https:');
  const cookieAttrs = `Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;

  const fail = async (e: unknown, request: Request, clear?: string): Promise<Response> => {
    const err = e instanceof RelyingPartyError ? e : new RelyingPartyError('server_error', 'sign-in failed');
    if (!(e instanceof RelyingPartyError)) console.error(e);
    const res = o.onError ? await o.onError(err, request) : defaultErrorPage(err);
    return clear ? withCookie(res, `${clear}=; ${cookieAttrs}; Max-Age=0`) : res;
  };

  return {
    async login(request) {
      try {
        const url = new URL(request.url);
        const q = new URLSearchParams(url.search);
        if (request.method === 'POST') {
          const ct = request.headers.get('content-type') ?? '';
          if (ct.includes('application/x-www-form-urlencoded')) for (const [k, v] of new URLSearchParams(await request.text())) q.append(k, v);
        } else if (request.method !== 'GET') {
          return new Response('method not allowed', { status: 405, headers: { allow: 'GET, POST' } });
        }
        const returnTo = safeReturnTo(q.get('return_to') ?? undefined);
        const iss = q.get('iss');
        // Section 5.8: `target_link_uri` is ignored; `iss` must be an accepted Issuer, and nothing is fetched otherwise.
        const begun = iss
          ? await rp.beginInitiated({ iss, loginHint: q.get('login_hint') ?? undefined, returnTo })
          : await rp.begin({ handle: q.get('handle') ?? q.get('login_hint') ?? undefined, issuer: q.get('issuer') ?? undefined, returnTo });
        const sealed = await seal(rp.options.stateSecret, begun.pending, TTL);
        return new Response(null, {
          status: 302,
          headers: { location: begun.url, 'set-cookie': `${cookieName(begun.pending.state)}=${sealed}; ${cookieAttrs}; Max-Age=${TTL}`, 'cache-control': 'no-store' },
        });
      } catch (e) {
        if (e instanceof RelyingPartyError && e.code === 'issuer_not_accepted') {
          return new Response(defaultErrorHtml(e), { status: 400, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
        }
        return fail(e, request);
      }
    },

    async callback(request) {
      const url = new URL(request.url);
      const state = url.searchParams.get('state') ?? '';
      const name = cookieName(state);
      try {
        const cookie = state ? readCookie(request, name) : undefined;
        const pending = cookie ? await unseal(rp.options.stateSecret, cookie) : null;
        const signIn = await rp.complete({ params: url.searchParams, pending });
        const res = await o.onSignIn(signIn, request);
        return withCookie(res, `${name}=; ${cookieAttrs}; Max-Age=0`); // `state` is consumed
      } catch (e) {
        return fail(e, request, state ? name : undefined);
      }
    },

    metadata() {
      return new Response(JSON.stringify(rp.clientMetadata(o.metadata)), { headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' } });
    },
  };
}

function withCookie(res: Response, cookie: string): Response {
  const headers = new Headers(res.headers);
  headers.append('set-cookie', cookie);
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/** Section 9 item 7: `access_denied` and `signup_limit_reached` are distinct outcomes; `error_description` is escaped. */
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
    case 'issuer_not_accepted':
      return 'This application does not accept agents from that provider.';
    case 'invalid_handle':
    case 'handle_required':
      return "Enter your agent's handle, for example scout@example.com.";
    case 'discovery_failed':
      return "The agent's provider could not be reached.";
    default:
      return 'The sign-in could not be completed.';
  }
}
function defaultErrorHtml(e: RelyingPartyError): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in not completed</title><body style="font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Sign-in not completed</h1><p>${escapeHtml(errorMessage(e))}</p><p style="color:#666;font-size:.85em">${escapeHtml(e.code)}</p></body>`;
}
function defaultErrorPage(e: RelyingPartyError): Response {
  return new Response(defaultErrorHtml(e), { status: 400, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
