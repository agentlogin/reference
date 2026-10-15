# @agentlogin/issuer

Reference issuer for [Agent Login Core 1.0](https://github.com/agentlogin/spec) (draft 0.1): an OpenID Provider that
signs software agents in with keys they hold. Written against the specification section by section so that the code
reads as a second description of the protocol; Hono for HTTP and jose for JOSE behind a `Store` interface.
The production storage target is [`@agentlogin/store-postgres`](../store-postgres/README.md), with normalized
records and atomic operations across instances. Memory and SQLite remain local reference/test adapters.
Requires Node.js 22.13 or newer.

Selected draft 0.2 requirements are implemented; the [compatibility status](../../docs/draft-0.2-status.md) pins the
target specification and records remaining gaps. `max_age` is parsed and stored with the transaction. A positive
value limits authentication age at code authorization, redemption and token issuance, including database waits;
stale completion ends `denied/login_required`, and a stale Token Request gets `invalid_grant`. Owner approval and
retries preserve the original accepted assertion time. Zero requires a fresh assertion for that transaction and
allows delayed approval/delivery within the ordinary transaction and code lifetimes. Nonempty wire values must
contain decimal digits only; an empty optional value is omitted per RFC 6749. Values larger than the safe timestamp
range act as an unlimited age bound within that range.

The stored age fields are additive and need no PostgreSQL schema migration. Stop old issuer processes before
upgrading: mixed versions can lose the new checks. Records created without an age constraint retain their previous
behavior. Custom `Store` adapters must implement the new atomic freshness checks even though the method signatures
are unchanged; run the shared store contract tests when upgrading an adapter.

```bash
npm run issuer            # http://localhost:3000, handle domain localhost, prints a generated ADMIN_TOKEN
DATABASE_URL=postgresql://... npm run issuer:migrate
DATABASE_URL=postgresql://... ISSUER=https://issuer.example HANDLE_DOMAINS=example.com,*.agents.example ADMIN_TOKEN=... SIGNING_JWK='{...}' npm run issuer
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
credential with no recorded session does not qualify either. `owner_verified_via` records a method supplied by the trusted operator (7.5); these historical labels are not assurance levels. The bootstrap markers do not themselves authenticate a human. All with `Authorization: Bearer ADMIN_TOKEN`.

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
| `activateKey`, `patchKey`, `revokeKey` | Match the exact enrollment; activation rechecks the proof window and claims global active-key exclusivity; explicit revocation also denies open transactions, removes bearer hashes from all matching transactions (including terminal ones), and invalidates codes and tokens |
| `updateTransaction` | Recheck a supplied transaction bearer before version/terminal checks; compare the open version, check subject identity, disable versions, transaction/assertion expiry and consent reliance, and commit cap admission, reservation and consent effects together |
| `completeTransaction` | Recheck a supplied transaction bearer before version/terminal checks; check the ready version, subject, expiry and reservation; complete, issue the code, update the Account and signup count, and release the reservation together |
| `setAgentEnabled`, `setAccountStatus` | Check the authorized Agent identity, increment the persistent disable version, and invalidate dependent records together |
| `deleteAgent`, `revokeAllKeys` | Check the immutable identity and apply all cleanup in the same transaction |
| `redeemCode`, `insertAccessToken` | Redeem once; validate lifecycle fences, and refuse token insertion for replayed codes |

`readTransaction` computes effective lifecycle/expiry state and retention without writing. Polling does not determine
whether a reservation counts or a credential remains valid. `currentTime` supplies the adapter's authoritative clock:
memory and SQLite use the supplied application clock, while PostgreSQL uses the database clock. Mutations recheck
expiry and the verified assertion window at acceptance. ID-token `iat` and `exp` come from the persisted access-token
issuance bounds, including when lock contention moves the database's issuance time past the application's timestamp.
A first assertion arriving at its original transaction deadline throws `TransactionExpiredError` without persisting
identity, a token, an extended Owner-approval deadline, consent, or quota. This check precedes the signed assertion's
window check. A first assertion also rechecks its key and enabled Agent identity/version, throwing
`AssertionSubjectError` (`unknown_key` or `key_revoked`) without consuming the challenge if authority changed.
Account denial remains an accepted assertion gate. First assertions also compare `expectedShareOwner` with the
current permission; a conflict has no effects and the handler recomputes Owner approval for the same verified
enrollment. Explicit revocation removes transaction bearer authority without changing existing terminal outcomes
or retention; natural key expiry preserves that bearer until retention ends. Review and completion pass the identified
bearer's hash to the atomic store operation, which throws `TransactionTokenError` if that authority was revoked.

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

Use PostgreSQL for multi-instance deployments; see its package README for schema migration, connection pools,
locking and recovery requirements. The following adapters are retained for local reference and testing.

`MemoryStore` implements these operations synchronously within one process. `SQLiteStore` runs that same state machine
inside `BEGIN IMMEDIATE`/`COMMIT` for mutations, with WAL and `synchronous=FULL`; reads use `BEGIN` and never update the
snapshot or acquire the writer lock. It uses Node’s built-in `node:sqlite` module (experimental in Node 22). Every
operation loads the complete fresh snapshot, and mutations serialize it back; no cached state or JavaScript lock
determines cross-process ownership. A failed commit rolls
back the whole operation. Tests exercise separate database connections, independent writer processes, persistence
across reopen, injected database write failures, and adversarial HTTP lifecycle schedules against both adapters.
SQLite has a known deadline limitation: it can apply a caller timestamp captured before waiting for the writer
lock. It is excluded from the PostgreSQL production hardening target and is not a production storage option.

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
the optional transaction-bearer checks and branded assertion-subject and transaction-expiry/token errors, and identity/version fields; do not run old and new issuers against the same store. This adapter creates a new schema;
there is no migration from third-party stores. The RP handler also now requires explicit shared callback storage
(see `@agentlogin/rp`). These fixes do not implement rate limiting or a production Owner authentication system, so
passing the tests is not a deployment approval.

Transactions now persist `clientPresentation`, a snapshot of only the public client name, logo, legal URLs and
Relay presentation that was displayed when authorization began. Authentication credentials, signup caps and
review policy remain on the current Client record. On upgrade, issuer startup cancels open transactions that
lack this snapshot with `access_denied`; users must start a new sign-in. It never backfills acceptance from
current metadata. Cancellation reads batches of at most 256 through `listLegacyTransactions`, uses the existing
atomic transition to release reservations, preserves effective expiry, and fixes terminal retention once. Custom
adapters must implement that filtered, bounded read and preserve `clientPresentation` on every transition.
PostgreSQL schema v3 includes its partial index; MemoryStore indexes legacy IDs and SQLite retains its documented
whole-snapshot storage behavior. Drain old issuer processes before upgrading; mixed versions are unsupported.

### Signing-key lifecycle

An issuer database now owns the active signing-key identity and the public-key
history. Private keys remain in the process's configured key ring. Every replica
reads shared authority before signing and rechecks withdrawal before delivery;
a replica missing the active private key fails closed.

`createIssuer({ signingJwks: [privateJwk, ...], jwksCacheSeconds: 3600 })` publishes
the supplied ES256 keys. Only an empty database selects the first key as its
bootstrap key. Adding a key to an existing database stages it without selecting
it. Use the returned `publishSigningKeys`, `activateSigningKey` and
`removeSigningKey` methods for lifecycle changes. Activation requires publication
to precede it on the authoritative database clock. Deploy the new private material
to every replica, verify the public JWKS, and then activate it.

Ordinary retirement is refused while a key is active or its issued-token lifetime
plus the longest JWKS cache lifetime has not elapsed. PostgreSQL reserves a
conservative extra minute when recording issuance to avoid a write for every
signature. `removeSigningKey(kid, true)` immediately withdraws a suspected
compromised key. Removed keys cannot be republished. Existing cached JWKS readers
may still trust a removed key until their cache expires; withdrawal is not an
instantaneous revocation of every relying-party session.

When upgrading a snapshot or PostgreSQL schema that predates signing history,
stop and drain every older issuer before migration, and include every previously
published key needed by outstanding tokens in the first configured upgrade ring.
The adapter cannot reconstruct those public keys from tokens or private keys that
were not supplied. Unknown issuance and cache history receives a fixed conservative
87,000-second overlap (Core T_TOKEN 600 plus maximum T_CACHE 86,400), even if the
new JWKS cache setting is zero. SQLite starts this deadline at the first successful
publication after upgrade; PostgreSQL fixes it at migration, after the old issuers
have stopped. The pending SQLite guard survives unrelated writes and restarts.
Publication transfers the guard atomically to the initial ring; later restarts and
publication never renew it. If a legacy key continues signing, each new signing
reservation preserves the maximum historical cache bound after that token expires;
only new issuance can extend the floor. This conservative behavior stays with that
legacy key until retirement. New installations and subsequently added keys keep
normal retirement timing. Compromised-key withdrawal still takes effect immediately.
This automatic bound covers Core-conforming historical lifetimes; deployments
that previously exceeded them must retain the prior keys for their longer overlap.

The standalone server also accepts `SIGNING_KEYS_FILE`, mutually exclusive with
`SIGNING_JWK`. Its JSON object has `keys` (private JWK array), and optional
`activateKid`, `retireKids`, and `compromisedKids`. Identifiers are SHA-256 JWK
thumbprints. Removed keys must be absent from `keys`. Atomically replace the file
and send `SIGHUP` to reload. The complete file is validated before changes begin.
Publication, activation and removal are separate durable operations: if activation
or retirement is premature, publication remains staged and the existing active
key remains selected. Emergency removal is never reversed by a later failure.
Publish a new key in one reload and activate it in a subsequent reload.

### Owner deletion and quota inheritance

`ownerDeletionRetentionSeconds` is a fixed non-negative integer, defaulting to
zero; the standalone variable is `OWNER_DELETION_RETENTION_SECONDS`. Metadata
publishes `op_policy_uri`, defaulting to the issuer's `/policy` document. A custom
`policyUri` / `OP_POLICY_URI` must describe the same configured period.

Trusted Owner integrations call `store.putOwner(owner, now)` after verified
address changes and `store.deleteOwner(id, ownerSub, now, retentionSeconds)` for
deletions. The latter must receive the configured published retention period.
Deletion invalidates dependent authority atomically. Counts are inherited only
while the deleted Owner's fixed deadline remains live; policy changes never move
that deadline. Zero ends inheritance immediately. Use fresh immutable Owner IDs
and subjects; deleted identities cannot be reused.

Quota membership records identify individual Account-creation events, including a new creation after Account deletion,
so repeated verification or address changes do not double-count an account.
Live Owners sharing a verified address share completed counts and pending
capacity. Moving an address preserves the Owner's existing counts and inherits
eligible history at the new address. Email identity preserves the parsed local
part exactly and compares lower-case A-label domains; no provider alias folding
is performed. These address links are personal data. PostgreSQL `cleanup()`
removes expired deleted-Owner links in bounded batches, while preserving copied
history still belonging to a live Owner. Schedule that cleanup regularly.
