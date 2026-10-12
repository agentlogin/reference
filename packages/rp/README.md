# @agentlogin/rp

Relying-party kit for [Agent Login](https://github.com/agentlogin/spec): let software agents sign in to your
application with an identity of their own. You receive a standard OpenID Connect ID Token that says `actor_type:
"agent"`, carries a stable `sub`, and names the accountable owner when you are registered and ask. Apache-2.0. Tracks
specification draft 0.1. Not yet published to npm: use it from this repository.

Runs on Node.js 22.13 or later. The handlers take and return the web-standard `Request` and `Response`, so they plug
into Hono, Next.js route handlers on the Node.js runtime, or Node's `http` through any fetch adapter. The kit does not
run on edge runtimes: discovery and every request to an issuer go through an address-filtering fetch that needs
`node:dns` and `node:http`. Bun and Deno are untested.

```ts
import { RelyingParty, SqliteCallbackStateStore, createHandlers, signInForm } from '@agentlogin/rp';

// Every process on this host uses the same persistent file. Protect its directory with application-only permissions.
const callbackStore = new SqliteCallbackStateStore('/var/lib/example-app/callbacks.sqlite');

const rp = new RelyingParty({
  clientId: 'https://app.example.org/client-metadata.json',   // Open Client: no registration, this URL is your identifier
  redirectUri: 'https://app.example.org/auth/agent/callback',
  issuers: ['https://issuer.example'],                         // the issuers you accept, exactly as they publish themselves
  stateSecret: process.env.STATE_SECRET!,                      // 32+ characters
});

const auth = createHandlers(rp, {
  callbackStore,
  metadata: { clientName: 'Example App', maxSignupsPerOwner: 5 },
  onSignIn: async (signIn) => {
    const account = await upsertAccount(signIn.agent.key);     // (iss, sub): never key on the handle
    const session = { account, agent: signIn.agent, live: rp.liveCheckOf(signIn) };
    return redirectWithSession(session, signIn.returnTo ?? '/');
  },
});
//   GET       /client-metadata.json  -> auth.metadata
//   GET, POST /auth/agent/login      -> auth.login      (form field `handle`, or `iss` + `login_hint`)
//   GET       /auth/agent/callback   -> auth.callback
// and in your page:  signInForm({ action: '/auth/agent/login' })
```

`auth.login` is also where an agent starts: it calls the URL with `iss` and `login_hint` (Section 5.8), and the
`agentlogin` client does that for you. Publish the URL as `initiateLoginUri` in `metadata`.

## What a sign-in gives you

`signIn.agent` identifies the agent and holds no personal data of its owner: `key` (issuer and `sub`), `handle`,
`name`, `ownerKey` (opaque, for per-owner limits). `signIn.owner` is present whenever an owner scope
(`owner_profile`, `owner_email`) was granted to a Registered Client: `name`, `email` (only when the issuer verified
it), `verifiedVia`, and `key` when `profile` was granted as well. Store it apart from agent data;
`rp.identityOf(claims)` gives the same mapping for claims you validated yourself. `signIn.accessToken` is a bearer
credential valid for ten minutes and usable only for the live check; do not log it and do not keep it longer.

Before an action with lasting effect, ask the issuer whether it still vouches for the agent:

```ts
await rp.recheck(session.live);
// throws RelyingPartyError 'revoked' after a key revocation or an account disable,
// and 'reauthentication_required' once the access token has expired: require a new sign-in then
```

## What the kit checks

| Requirement | Where |
| --- | --- |
| `state`, `nonce`, PKCE `S256` on every request; `login_hint` when the handle is known (5.1, 9) | `begin` |
| The issuer recorded per `state`; `iss` on the redirect checked; code sent only to that issuer; one callback per sign-in (5.7 step 1) | `complete`, `callback` |
| ID Token: pinned algorithm (ES256), key by `kid`, `iss`, `aud`, required `exp`, `iat`, `nonce`, `actor_type` (5.7) | `validateIdToken` |
| Handle-to-issuer binding; `home_iss` only from the configured Relay and within its `home_issuers` (2.5) | `validateIdToken` |
| No Relay beside a Home Issuer it relays, judged by the Relay's metadata as it is now (9 item 10) | `begin`, `complete`, `validateIdToken` |
| Discovery only for presented handles, cached per the response; address filtering, 64 KiB and 10 s limits on every fetched endpoint (2.2, 9) | `resolve` |
| UserInfo live check, `sub` equality, `401` as revocation (9) | `recheck` |
| Agent-initiated start: only accepted issuers, nothing sent to any other, `target_link_uri` ignored (5.8) | `login` |
| Client ID Metadata Document (4.2) | `metadata` |
| `access_denied` and `signup_limit_reached` presented distinctly; nothing from the issuer is echoed (9) | `errorMessage`, `errorPage` |

## Choosing issuers

List the issuers you trust in `issuers`. Add one Relay (`{ issuer, relay: true }`) to accept every home issuer that
Relay accepts through a single connection; do not also list a home issuer the Relay relays, or per-owner caps count
twice. The kit refuses that configuration with `configuration_error`, and checks it on every sign-in against the
Relay's current metadata, because a Relay can start relaying an issuer after you configured it. Or set `federation: 'any'` to accept whichever issuer a presented
handle designates, and apply your own per-issuer limits.

A Registered Client sets `clientId`, `clientSecret` and optionally `scopes` on the issuer's entry and may request
`owner_profile` and `owner_email`. A secret is sent only to the issuer it was configured for; a top-level
`clientSecret` is accepted only with exactly one issuer.

## Errors

Every failure is a `RelyingPartyError` with a `code` from a fixed set (`RelyingPartyErrorCode`), a `message` written
by the kit, a `status` (400, 500 for `configuration_error` or `state_store_failed`, 502 for upstream failures) and, for errors the issuer
returned, its untrusted `description`. Codes from the issuer: `access_denied`, `signup_limit_reached`,
`consent_required`, `interaction_required`, `invalid_request`, `invalid_scope` and the other OAuth codes; any other
value becomes `issuer_error`. Codes from the kit: `invalid_state`, `duplicate_callback`, `issuer_mismatch`,
`issuer_not_accepted`, `invalid_id_token`, `handle_binding_failed`, `token_request_failed`, `discovery_failed`,
`userinfo_failed`, `revoked`, `reauthentication_required`, `invalid_handle`, `handle_required`, `configuration_error`, `state_store_failed`.
Whatever your `onSignIn` throws is not caught.

## Callback state and deployment

`createHandlers` requires a `callbackStore`. Login registers a state before returning its cookie; the callback
atomically consumes it before contacting the issuer. Every handler instance and application replica must use the
same store. A consumed state stays consumed even when token exchange times out, ID Token validation fails, or
`onSignIn` throws: the caller must start a new sign-in. Re-exchanging a code can revoke an earlier successful
session at the issuer, so retrying an uncertain exchange is unsafe.

`SqliteCallbackStateStore` provides durable atomic registration and consumption across processes on one host,
using Node.js `node:sqlite`, WAL, and full synchronous writes. Close it when the application shuts down. Use a
local filesystem, keep the database and WAL files together, and do not restore stale snapshots while cookies they
could resurrect remain valid. For multiple hosts, implement `CallbackStateStore` against a shared database. The
store contract requires insert-if-absent registration and an atomic conditional update from unused to used only
before the original expiry. Never reset existing records, release claims, or evict unexpired records. Missing
records fail closed; losing the store ends pending sign-ins instead of allowing cookie replay.

`MemoryCallbackStateStore` is for development and single-process tests; share the same instance between handlers.
It has a configurable capacity (default 10,000 states) and refuses new sign-ins when full instead of evicting live
records. Storage failures return `state_store_failed` (HTTP 500), without exchanging a code. Low-level callers of
`rp.complete` must implement the same atomic consumption before calling it; only `createHandlers` manages this
automatically.

## Limits to know

- A started sign-in is valid for 15 minutes (`pendingTtlSeconds`, up to a day). One that waits longer for the
  agent's owner has to be started again.
- The per-sign-in record (state, nonce, PKCE verifier, issuer) travels in an encrypted `__Host-` cookie. The shared
  callback store holds only opaque state digests, expiry times and consumption flags. Changing `stateSecret` ends
  the sign-ins in progress.
- Not implemented: `private_key_jwt` client authentication, the DNS fallback of Section 2.3. EdDSA ID Tokens are
  accepted only when you set `idTokenAlgs`.

See `examples/rp-hono` for a runnable application.
