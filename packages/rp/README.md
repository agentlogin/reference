# @agentlogin/rp

Relying-party kit for [Agent Login](https://github.com/agentlogin/spec): let software agents sign in to your
application with an identity of their own. You receive a standard OpenID Connect ID Token that says `actor_type:
"agent"`, carries a stable `sub`, and names the accountable owner when you are registered and ask. Apache-2.0. Tracks
specification draft 0.1.

```ts
import { RelyingParty, createHandlers, signInForm } from '@agentlogin/rp';

const rp = new RelyingParty({
  clientId: 'https://app.example.org/client-metadata.json',   // Open Client: no registration, this URL is your identifier
  redirectUri: 'https://app.example.org/auth/agent/callback',
  issuers: ['https://issuer.example'],                         // the issuers you accept
  stateSecret: process.env.STATE_SECRET!,                      // 32+ characters
});

const auth = createHandlers(rp, {
  metadata: { clientName: 'Example App', maxSignupsPerOwner: 5 },
  onSignIn: async (signIn) => {
    const account = await upsertAccount(signIn.agent.key);     // (iss, sub): never key on the handle
    return redirectWithSession(account, signIn.returnTo ?? '/');
  },
});
// Web-standard handlers (Request -> Response): Hono, Next.js route handlers, Workers, Bun, Deno, Node adapters
//   GET  /client-metadata.json     -> auth.metadata
//   GET/POST /auth/agent/login     -> auth.login      (form field `handle`, or `iss` + `login_hint`)
//   GET  /auth/agent/callback      -> auth.callback
// and in your page:  signInForm({ action: '/auth/agent/login' })
```

Before an action with lasting effect, ask the issuer whether it still vouches for the agent:

```ts
await rp.recheck(session.signIn);   // throws RelyingPartyError('revoked') after key revocation or account disable
```

What the kit does for you, by specification section:

| Requirement | Where |
| --- | --- |
| `state`, `nonce`, PKCE `S256` on every request; `login_hint` when the handle is known (5.1, 9) | `begin` |
| The issuer recorded per `state`; `iss` on the redirect checked; code sent only to that issuer (5.7 step 1) | `complete` |
| ID Token: pinned algorithm (ES256), key by `kid`, `iss`, `aud`, `exp`, `iat`, `nonce`, `actor_type` (5.7) | `validateIdToken` |
| Handle-to-issuer binding, `home_iss` only from a configured Relay (2.5) | `validateIdToken` |
| Discovery only for presented handles, cached, with address filtering on every fetched endpoint (2.2, 9) | `resolve` |
| UserInfo live check, `sub` equality, `401` as revocation (9) | `recheck` |
| Agent-initiated start: only accepted issuers, `target_link_uri` ignored (5.8) | `login` handler |
| Client ID Metadata Document (4.2) | `metadata` handler |
| `access_denied` and `signup_limit_reached` presented distinctly, `error_description` escaped (9) | `errorMessage`, default error page |

Choosing issuers: list the ones you trust (`issuers`); add one Relay (`{ issuer, relay: true }`) to accept every home
issuer that Relay accepts through a single connection; or set `federation: 'any'` to accept whichever issuer a
presented handle's domain designates, and apply your own per-issuer limits. A Registered Client sets `clientId` and
`clientSecret` (per issuer when you accept several) and may request `owner_profile` and `owner_email`.

The per-sign-in record (state, nonce, PKCE verifier, issuer) travels in an encrypted HttpOnly cookie, so the kit keeps
no server-side state. What stays your responsibility: your session, keying accounts on `agent.key` and per-owner
limits on `agent.ownerKey`, storing owner data apart from agent data, and not logging tokens (Section 9).

Not implemented yet: `private_key_jwt` client authentication, EdDSA ID Tokens by default (opt in with
`idTokenAlgs`), the DNS fallback of Section 2.3. See `examples/rp-hono` for a runnable application.
