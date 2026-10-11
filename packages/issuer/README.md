# @agentlogin/issuer

Reference issuer for [Agent Login Core 1.0](https://github.com/agentlogin/spec) (draft 0.1): an OpenID Provider that
signs software agents in with keys they hold. Written against the specification section by section so that the code
reads as a second description of the protocol; Hono for HTTP, jose for JOSE, an in-memory store behind a small
`Store` interface.

```bash
npm run issuer            # http://localhost:3000, handle domain localhost, prints a generated ADMIN_TOKEN
ISSUER=https://issuer.example HANDLE_DOMAINS=example.com,*.agents.example ADMIN_TOKEN=... SIGNING_JWK='{...}' npm run issuer
```

Endpoints (spec section in brackets): `/.well-known/openid-configuration` and `/.well-known/jwks.json` (2.4, 7.7),
`/.well-known/webfinger` for served handles (2.2), `/authorize` GET and POST (5.1–5.3), `/transactions/{id}` with
`/assertion`, `/review`, `/continue/{secret}` and the `/wait` page (6), `/token` and `/userinfo` (5.6, 3.3),
`/register` (RFC 7591 with the admin token as initial access token, 4.3), `/agents/{handle}/...` management (7.2, 7.8),
`/owner/transactions/{id}` and `/decision` (6.6, API form).

Owner sign-in by email (7.5; how an Owner authenticates is outside the wire protocol): `POST /owner/sessions/email
{email}` sends a one-time code through the `sendOwnerCode` option of `createIssuer` (the standalone server prints it
in development mode; without the option the endpoint answers `501`), and `POST /owner/sessions/email/verify
{email, code}` returns an Owner Credential. That credential comes from a one-time code alone, so it manages the
Owner's Agents but neither approves a transaction nor grants `share_owner` (6.6, 7.8).

A registration stating `relay_issuer` (4.4) is accepted only when every redirect URI is on that host and the Relay's
metadata can be fetched under the protections of 2.2; its `op_policy_uri`, as of registration, is what the approval
view shows.

Bootstrap, outside the specification: `POST /admin/owners {email, name, verified_via, session_auth}` returns an Owner
Credential; `POST /admin/agents {handle, owner_id, name}`; `POST /admin/credentials {owner_id, kind: "delegated",
handle}` or `{owner_id, kind: "owner", session_auth}`; `PATCH /admin/agents/{handle} {enabled}` (Section 7.4 effects);
`DELETE /admin/agents/{handle}` (deletes the Agent with its keys, Consent Records, Accounts and Delegated Credentials;
the Section 7.6 count is retained). `session_auth` states how the session that obtained an Owner Credential
authenticated the Owner: `passkey`, `oidc`, `domain`, `email_factor` or `email_only`. Only the first four approve a
transaction or grant `share_owner` (Sections 6.6, 7.8); a caller that omits it gets `email_only`, and a stored
credential with no recorded session does not qualify either. `owner_verified_via` reports the strongest method among
`verified_via` and the sessions stated (7.5). All with `Authorization: Bearer ADMIN_TOKEN`.

Status: passes every check of `@agentlogin/conformance` (`npm test`). Not yet implemented: Ed25519 agent keys,
`private_key_jwt`, rate limits (6.7), Owner authentication by passkey, OIDC or domain (credentials from such sessions
are issued by the bootstrap API on the operator's word) and the HTML pages for Owner sign-in and approval,
Relay profile (8), a database-backed `Store`, the `pairwise` subject type. Development mode (`INSECURE_DEV=1`, or an
`http` issuer) permits loopback clients and private addresses in metadata fetches; never run it that way in production.

Concurrency: the issuer holds no locks in process, so several issuer processes may share one store. Every rule that
must hold when requests arrive together is one `Store` operation that carries its own preconditions, and a shared
store has to make each of them atomic (one conditional write or one database transaction):

| Operation | Precondition it enforces |
| --- | --- |
| `updateTransaction` | the transaction is still at the `version` that was read (compare and swap) |
| `insertKey` | the key is not enrolled now, for this handle or another, and was not revoked for this handle (7.2) |
| `activateKey`, `patchKey` | the key is still in the `enrollment` that was read; to activate, still pending with its unused challenge |
| `revokeKey`, `setAgentEnabled`, `setAccountStatus` | none; the write is the point after which nothing new is issued |
| `voidCodes`, `revokeAccessTokens` | none; each matching record changes in one write |
| `redeemCode` | the code exists, is unexpired, not void and not yet used (5.6) |
| `reserveSignup`, `recordSignIn` | the Agent is counted once and the Owner's cap is not exceeded (7.6) |
| `grantConsent`, `touchConsent` | one record per (Agent, client): created or extended, never duplicated (6.4) |

A rule that spans two records is kept by writing one and then reading the other again. A revocation writes the key
first and then ends the transactions, codes and tokens that key asserted; an assertion and a token exchange read
the key again after their own write and undo it when the key has gone, and UserInfo reads the key on every call. Each key has an
`enrollment` generation, and transactions, codes and tokens are bound to it, so enrolling the same `kid` again after
it expired revives nothing issued before. Expiry is computed when a record is read and is never a stored state.
`MemoryStore` meets all of this within one process and returns copies; `test/lifecycle.test.ts` runs two issuer
instances over one store.
