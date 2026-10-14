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
import { RelyingParty, createHandlers, signInForm } from '@agentlogin/rp';
import { PostgresCallbackStateStore } from '@agentlogin/rp-store-postgres';

// Every application replica uses this primary database and schema.
const callbackStore = new PostgresCallbackStateStore({ connectionString: process.env.RP_DATABASE_URL! });
await callbackStore.verifySchema(); // Run agentlogin-rp-migrate separately before startup.

const rp = new RelyingParty({
  clientId: 'https://app.example.org/client-metadata.json',   // Open Client: no registration, this URL is your identifier
  redirectUri: 'https://app.example.org/auth/agent/callback',
  issuers: ['https://issuer.example'],                         // the issuers you accept, exactly as they publish themselves
  stateSecret: process.env.STATE_SECRET!,                      // 32+ characters, shared by every replica
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
// Drain HTTP requests, then await callbackStore.close() during shutdown.
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
| Callback members and session/issuer binding checked before state consumption; code sent only to the recorded issuer; one callback per sign-in (5.7 step 1) | `preflightCallback`, `complete`, `callback` |
| ID Token: pinned algorithm (ES256), key by `kid`, `iss`, `aud`, required `exp`, `iat`, `nonce`, `actor_type` (5.7) | `validateIdToken` |
| Requested `max_age` and request time bound to state; required `auth_time`, exact positive age bound, fresh assertion for zero (5.1, 5.7) | `begin`, `complete`, `validateIdToken` |
| Returned handle matches the expected handle bound to state; handle-to-issuer binding; `home_iss` only from the configured Relay and within its `home_issuers` (2.5) | `validateIdToken` |
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

## Authentication freshness

Set `maxAge` on `RelyingPartyOptions` to request a maximum authentication age in seconds; trusted application
code can override it with `rp.begin({ maxAge: ... })`. Values must be non-negative safe integers. The login
handler ignores `max_age` in incoming query parameters and forms, so an external caller cannot weaken the
application's policy. With no configured or per-request value, `max_age` is omitted.

The pending sign-in binds both `maxAge` and `authenticationRequestedAt` to the encrypted state. For a positive
value, the kit requires a finite, non-negative numeric `auth_time` (fractional seconds are allowed) and rejects
an ID Token when its age exceeds that value, including time spent fetching keys or checking the handle.
There is no extra age tolerance. `maxAge: 0` instead requires
`auth_time` to be at or after the original request time; an Owner approval delay does not turn zero into a delivery
deadline. Future authentication times and times after the token's `iat` are rejected. Issuer and application
clocks must therefore be synchronized; the specification's `iat` tolerance does not extend the age bound.
`maxAge` is checked when accepting a sign-in. Configure application session lifetimes separately and continue
using `rp.recheck` before actions with lasting effects.

Low-level `validateIdToken` callers must supply the original `maxAge` and `authenticationRequestedAt` together
in `IdTokenValidationOptions`, from their protected pending state. Never derive them from callback parameters.
Malformed or incomplete age context is rejected. These checks implement draft 0.2 Sections 5.1 and 5.7;
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) requires `auth_time` when
`max_age` is requested and defines zero as active authentication.

## Errors

Every failure is a `RelyingPartyError` with a `code` from a fixed set (`RelyingPartyErrorCode`), a `message` written
by the kit, a `status` (400, 500 for `configuration_error` or `state_store_failed`, 502 for upstream failures) and, for errors the issuer
returned, its untrusted `description`. Codes from the issuer: `access_denied`, `signup_limit_reached`,
`consent_required`, `interaction_required`, `login_required`, `invalid_request`, `invalid_scope` and the other OAuth codes; any other
value becomes `issuer_error`. Codes from the kit: `invalid_state`, `duplicate_callback`, `issuer_mismatch`,
`issuer_not_accepted`, `invalid_id_token`, `handle_binding_failed`, `token_request_failed`, `discovery_failed`,
`userinfo_failed`, `revoked`, `reauthentication_required`, `invalid_handle`, `handle_required`, `configuration_error`, `state_store_failed`.
Whatever your `onSignIn` throws is not caught.

## Callback state and deployment

`createHandlers` requires a `callbackStore`. Login registers a state before returning its cookie; the callback
validates protocol response members and session/issuer binding, then atomically consumes state before contacting
the issuer. Malformed or unbound responses preserve the pending state and cookie. A valid issuer error consumes
state without a token request. Every handler instance and application replica must use the
same store. A consumed state stays consumed even when token exchange times out, ID Token validation fails, or
`onSignIn` throws: the caller must start a new sign-in. Re-exchanging a code can revoke an earlier successful
session at the issuer, so retrying an uncertain exchange is unsafe.

Use [`@agentlogin/rp-store-postgres`](../rp-store-postgres/README.md) for replicas on different hosts. It stores
opaque state digests in indexed PostgreSQL rows and checks expiry after acquiring the callback row's lock. Run its
migration before deployment, verify the schema at startup, and schedule bounded `cleanup()` calls. Use the primary
database and the same stable `stateSecret`, client ID and redirect URI across replicas. Keep application and database
clocks synchronized. This package is separate from the issuer's `@agentlogin/store-postgres`; neither stores your
application sessions or accounts.

`SqliteCallbackStateStore` provides durable atomic registration and consumption across processes on one host,
using Node.js `node:sqlite`, WAL, and full synchronous writes. Close it when the application shuts down. Use a
local filesystem, keep the database and WAL files together, and do not restore stale snapshots while cookies they
could resurrect remain valid. The
store contract requires insert-if-absent registration and an atomic conditional update from unused to used only
before the original expiry. Never reset existing records, release claims, or evict unexpired records. Missing
records fail closed; losing the store ends pending sign-ins instead of allowing cookie replay.

Acknowledged claims must survive database failover. Restoring older callback data can undo consumption; before
serving traffic after a rollback or restore, rotate `stateSecret` on every replica and reject pending cookies made
with the previous secret. Do not accept old secrets during this recovery. Start new sign-ins instead.

`MemoryCallbackStateStore` is for development and single-process tests; share the same instance between handlers.
It has a configurable capacity (default 10,000 states) and refuses new sign-ins when full instead of evicting live
records. Storage failures return `state_store_failed` (HTTP 500), without exchanging a code. Low-level callers must
call `rp.preflightCallback({ params, pending })`, atomically consume their server-side pending state, then call
`rp.complete({ params, pending })`, including for error responses. `complete` repeats the same preflight checks but
does not manage consumption; only `createHandlers` manages this automatically.

Keep a known handle in `pending.loginHint`; `begin` binds it to state and sends it as `login_hint`. Completion
compares any returned `email` with that handle, preserving local-part case and ignoring A-label domain case.
Callback parameters cannot replace the bound handle. Relay tokens without `email` require a pre-bound handle
whose discovery designates `home_iss`. Callers using `validateIdToken` directly must pass the bound handle as
`expectedHandle` when known.

## Limits to know

- A started sign-in is valid for 15 minutes (`pendingTtlSeconds`, up to a day). One that waits longer for the
  agent's owner has to be started again.
- The per-sign-in record (state, nonce, PKCE verifier, issuer) travels in an encrypted `__Host-` cookie. The shared
  callback store holds only opaque state digests, expiry times and consumption flags. Changing `stateSecret` ends
  the sign-ins in progress.
- Not implemented: `private_key_jwt` client authentication, the DNS fallback of Section 2.3. EdDSA ID Tokens are
  accepted only when you set `idTokenAlgs`.

See `examples/rp-hono` for a runnable application.
