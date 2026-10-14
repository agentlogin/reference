# @agentlogin/issuer

Reference issuer for [Agent Login Core 1.0](https://github.com/agentlogin/spec) (draft 0.1): an OpenID Provider that
signs software agents in with keys they hold. Written against the specification section by section so that the code
reads as a second description of the protocol; Hono for HTTP, jose for JOSE, an in-memory store behind a small
`Store` interface, with memory and transactional SQLite adapters. Requires Node.js 22.13 or newer.

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

Status: passes the automated probes in `@agentlogin/conformance` (`npm test`); the report keeps evidence gaps,
including unverified entropy generation, explicit. Not yet implemented: Ed25519 agent keys,
`private_key_jwt`, rate limits (6.7), Owner authentication by passkey, OIDC or domain (credentials from such sessions
are issued by the bootstrap API on the operator's word) and the HTML pages for Owner sign-in and approval,
Relay profile (8), the `pairwise` subject type. Development mode (`INSECURE_DEV=1`, or an
`http` issuer) permits loopback clients and private addresses in metadata fetches; never run it that way in production.

Concurrency and persistence: every guarantee spanning records is a single `Store` operation. A database adapter
must commit the full transition, including its preconditions and effects, in one database transaction:

| Operation | Atomic guarantee |
| --- | --- |
| `putAgent` | Insert only when the handle is absent; an existing identity is never overwritten |
| `resolveManagement`, `readManagementKeys`, `readManagementAccounts` | Read the credential, immutable Agent identity and protected resources in one snapshot; reject stale authorization |
| `insertKey` | The credential, Owner and immutable Agent subject still match the authorization; enforce Agent-scoped pending uniqueness and revocation history |
| `activateKey`, `patchKey`, `revokeKey` | Match the exact enrollment; activation rechecks the proof window and claims global active-key exclusivity; revocation also denies transactions and invalidates codes and tokens |
| `updateTransaction` | Compare the open transaction version, check subject identity, disable versions, assertion expiry and consent reliance, and commit cap admission, reservation and consent effects together |
| `completeTransaction` | Check the ready version, subject, expiry and reservation; complete, issue the code, update the Account and signup count, and release the reservation together |
| `setAgentEnabled`, `setAccountStatus` | Check the authorized Agent identity, increment the persistent disable version, and invalidate dependent records together |
| `deleteAgent`, `revokeAllKeys` | Check the immutable identity and apply all cleanup in the same transaction |
| `redeemCode`, `insertAccessToken` | Redeem once; validate lifecycle fences, and refuse token insertion for replayed codes |

`readTransaction` computes effective lifecycle/expiry state and retention without writing. Polling does not determine
whether a reservation counts or a credential remains valid. `currentTime` supplies the adapter's authoritative clock:
memory and SQLite use the supplied application clock, while PostgreSQL uses the database clock. Mutations recheck
expiry and the verified assertion window at acceptance. ID-token `iat` and `exp` come from the persisted access-token
issuance bounds, including when lock contention moves the database's issuance time past the application's timestamp.

Agent subjects never change or transfer to a replacement at the same handle. Keys remember the authorizing subject;
transactions, codes and access tokens retain that subject, their key enrollment, and Agent/Account disable versions.
Management authorization resolves the credential and Agent together. Protected reads validate that authorization
with the returned records; protocol key mutations revalidate the credential, session permissions and Agent identity
inside the write. A delegated request cannot acquire a replacement Agent's identity after its credential was deleted.
The optional authorization arguments of `patchKey` and `revokeKey` are mandatory for protocol callers; omission is
reserved for trusted internal lifecycle operations. Custom adapters must implement the three management snapshot
methods and honor these mutation preconditions; the stored format does not change.
Unproved pending enrollments are scoped to the Agent: an attacker knowing only a public key cannot reserve it
against another Agent. Only successful proof activation claims the one active enrollment for that key across the
issuer. Conflicting valid proofs fail with `400 invalid_request`; other enrollments remain untouched. Store callers
should use `getKey(kid, handle)`; an unscoped lookup returns an active or sole record and refuses ambiguous pending keys.
Pending timeout cleanup uses `deleteKey(kid, enrollment, pendingExpiredAt)`, which atomically requires the same
enrollment to remain pending and expired. A stale reader cannot delete a key that another request activated.
Disable versions increase even if an Agent or Account is subsequently enabled. Delayed work cannot become valid again
simply because the current enabled flag is true. Reservation helpers are private to the state machine: a losing
assertion cannot release the winning assertion's place. Consent changes commit with their transition, so delayed
cleanup cannot write to a replacement Agent. Previously granted scopes carry forward only while the redirect host,
client name, terms URI and policy URI remain unchanged; accepting changed terms replaces the scope set. Invalidation
preserves an expired transaction's original terminal time and never restarts its retention window.

`MemoryStore` implements these operations synchronously within one process. `SQLiteStore` runs that same state machine
inside `BEGIN IMMEDIATE`/`COMMIT` for mutations, with WAL and `synchronous=FULL`; reads use `BEGIN` and never update the
snapshot or acquire the writer lock. It uses Node’s built-in `node:sqlite` module (experimental in Node 22). Every
operation loads the complete fresh snapshot, and mutations serialize it back; no cached state or JavaScript lock
determines cross-process ownership. A failed commit rolls
back the whole operation. Tests exercise separate database connections, independent writer processes, persistence
across reopen, injected database write failures, and adversarial HTTP lifecycle schedules against both adapters.

Snapshot format 2 stores scoped key enrollments. Memory and SQLite read version 1 snapshots and convert their
key map in memory; the next mutation writes version 2. Stop old issuer instances before upgrading, and do not mix
versions or roll back the binary against a version 2 snapshot. Keep a backup for rollback of the whole deployment;
restoring it still requires the security-state reconciliation described in the implementation guidance.

```ts
import { createIssuer, SQLiteStore } from '@agentlogin/issuer';
const store = new SQLiteStore('/private/app/issuer.sqlite');
const { app } = await createIssuer({ issuer, handleDomains, adminToken, signingJwk, store });
// Drain requests before calling store.close().
```

For the standalone server, set `DATABASE_PATH` and a persistent `SIGNING_JWK`. All issuer processes sharing the
database must use the same issuer configuration and signing key. Keep the database and its WAL files in a private
application directory on a local filesystem; the adapter is for processes on one host, not a network filesystem.
Back up a live database using SQLite's backup facilities, not by copying only the main file while WAL is active.
The adapter deliberately serializes mutations and rewrites the full snapshot. Reads still parse the full snapshot,
and synchronous SQLite calls block the Node event loop. It is a durable, auditable reference adapter, not a
high-throughput database design. Large deployments need normalized/indexed storage,
retention cleanup, capacity planning and operational testing while preserving this transaction contract.

Migration: the `Store` API and stored records have changed. Custom adapters must implement `currentTime`, read-only
`readTransaction`, the new atomic operations, assertion/proof-window and consent-context checks, persisted token issuance timestamps
and identity/version fields; do not run old and new issuers against the same store. This adapter creates a new schema;
there is no migration from third-party stores. The RP handler also now requires explicit shared callback storage
(see `@agentlogin/rp`). These fixes do not implement rate limiting or a production Owner authentication system, so
passing the tests is not a deployment approval.
