# PostgreSQL issuer store

`@agentlogin/store-postgres` is a separate, asynchronous PostgreSQL adapter for
`@agentlogin/issuer`. It stores one row per entity, uses indexed lookups, and commits each
protocol mutation in a `SERIALIZABLE` transaction. It does not load a database snapshot
or make polling a write. PostgreSQL 17 is exercised by the integration suite.

```ts
import { createIssuer } from '@agentlogin/issuer';
import { PostgresStore } from '@agentlogin/store-postgres';

const store = new PostgresStore({ connectionString: process.env.DATABASE_URL });
await store.db.verifySchema(); // Run agentlogin-migrate separately before startup.
const { app } = await createIssuer({
  issuer: 'https://issuer.example',
  handleDomains: ['issuer.example'],
  store,
  signingJwk, // Stable signing key shared by all issuer instances.
});
// Drain HTTP requests, then await store.close() during shutdown.
```

Use one authoritative primary for security decisions. A stale replica or cache can
restore a credential's apparent validity after revocation. Supply an externally
configured `pg.Pool` through `pool` when custom TLS, certificate verification, or pool
instrumentation is needed. Do not disable certificate verification in production.
`pool` and `connectionString` are mutually exclusive; the caller owns and closes an
external pool. Otherwise `close()` drains the adapter's own pool.

The installed package includes `agentlogin-migrate`; from the repository, run
`npm run issuer:migrate`. Both require `DATABASE_URL`, accept `DATABASE_SCHEMA`
(default `agentlogin`) and `DATABASE_POOL_SIZE` (default 1 for the migration command),
and print only the schema/version on success. Use the migration role for this command.
Normal server startup verifies the schema version and does not perform DDL.

Schema version 2 upgrades version 1 in place, preserving enrollments and their
dependent authorizations. Stop old adapter instances before migration: version 1
assumes one row per key thumbprint and cannot safely use the new key layout.

The default schema is `agentlogin`. Names must be lowercase SQL identifiers, at most
63 characters, and cannot start with `pg_`. Schema migrations are versioned and
transactional. Concurrent migration commands coordinate through a migration-only
advisory lock; issuer operations do not use that lock. Migration does not import a
SQLite snapshot. Give ordinary issuer connections DML privileges and function
execution only; use a separate deployment role for schema changes and migrations.

## Constraints and identity

The schema contains `owners`, `agents`, `credentials`, `owner_codes`, `keys`,
`revoked_keys`, `clients`, `transactions`, `codes`, `access_tokens`, `accounts`,
`consents`, `quotas`, and `reservations`. JSONB is used for an individual protocol
record. Stored generated columns extract typed identifiers, lifecycle values,
versions, and expiry timestamps for constraints and indexes. Changing a payload
therefore cannot silently leave its indexed values stale.

* Owners have unique subjects. SQL triggers prevent updates to an owner's ID/subject
  and an agent's handle/subject/owner binding. Agents have a unique current handle and
  unique immutable subject. Management
  operations revalidate the authorized subject and credential inside their mutation.
  Deleting and reassigning a handle does not transfer accounts, consent, or keys.
* Pending key challenges belong to `(handle, kid)`; they do not reserve another
  agent's public key. Enrollment identifiers are unique. A partial unique index
  permits only one active enrollment per thumbprint across the issuer. Activation
  retires an expired active enrollment before claiming exclusivity; a concurrent
  unique-index conflict rejects the losing activation. A stale request cannot
  change another enrollment. Permanent `(handle, kid)` revocation records prevent
  prohibited enrollment reuse.
* Accounts and consents use `(agent_sub, client_id)` identity, with a unique current
  `(handle, client_id)` lookup. Codes are unique by transaction; access tokens are
  unique by transaction and refer to their code. Token hashes are unique.
* Quota rows hold permanent owner/client signup counts. Deleting an account or agent
  never decrements these counts. Reservations are separately owned by transaction ID
  and bind the immutable agent identity. Several live reservations for one agent
  consume only one pending place.

Historical transactions, codes, and tokens intentionally do not cascade from a live
agent or key. Those records can be needed for polling outcomes and replay protection
after the identity itself has been removed. The only historical dependency foreign key
is the token's transaction reference to its code; cleanup must remove dependents first.

## Concurrency contract

Every mutation uses one checked-out connection from a bounded asynchronous pool and
runs at `SERIALIZABLE`. The entire operation—including authorization, expiry,
reservation decisions, and SQL—is retried after confirmed `40001` or `40P01` rollbacks.
Retries are bounded and include exponential delay with jitter. Other errors are not
silently retried.

Operations affecting quota admission or completion take the owner/client quota row
lock before other writes. Where an operation needs several quota rows, it acquires
pairs in a consistent order. This protects admission even before an account exists.
The lock localizes deliberate waiting to the affected pair; it does **not** eliminate
serialization failures because the transaction's snapshot can predate its wait.

Authorization checked before a transaction is only a candidate: relevant identity,
key, credential, and disable versions are checked again inside it. Revocation performs
indexed invalidation of dependent transactions, codes, tokens, and reservations.
Authoritative lifecycle checks remain necessary at later transitions and UserInfo.
Background deletion never determines whether a credential is valid.

Polling uses `READ COMMITTED READ ONLY` and computes effective status without writing.
Management resolution and protected reads join the credential, Agent identity and requested records in one
statement snapshot. Individual key mutations revalidate the retained authorization inside their serializable write.
An unmaterialized expiry is exposed with its original expiry as terminal time, rather
than restarting retention when a reader or later revocation first notices it. A raw
transaction lookup is also available for compare-and-swap transitions.

No discovery request, signature verification, signing operation, or external callback
runs inside a database transaction. Tests can use `onCheckpoint` to stop a transaction
at documented phases; production has no checkpoint hooks by default.

## Time contract

`app_now()` wraps `floor(extract(epoch FROM clock_timestamp()))`; it does not use
PostgreSQL `now()`, which is fixed at transaction start. Mutations sample it after
quota waits and validate again on every retry. Caller-supplied timestamps do not
replace this clock. Assertion validity windows also reach the atomic acceptance
operation so that lock contention cannot extend a signed assertion's lifetime.

Token creation asks the store clock for its initial timestamp. Token insertion records
its accepted issuance time and expiry; signed token claims use that persisted result.
Some initial metadata and expiry bounds originate from the application's clock; the
database still applies fresh final expiry checks. Keep application and database clocks
synchronized for these bounds, external assertions, and JWT interoperability.
Tests replace `app_now()` only in their isolated test schema;
there is no production configuration switch that accepts a request-provided clock.

Index predicates contain no time functions. Expired enrollment slots and reservations
are handled inside the operation that needs to reuse or count them. Preserved expiry
and terminal timestamps are never advanced by retry, invalidation, or cleanup.

## Failure recovery contract

There is no generic operation journal. Conclusive rereads use natural durable identity
such as an enrollment ID, transaction version/code hash, or access-token hash.
Code redemption additionally records a random attempt marker, redemption time, and
bounded issuance window. The same marker survives an internal retry; a separate HTTP
request has a new marker and remains a replay, including after the code was redeemed.

After an error around `COMMIT`, the connection is discarded. Where an operation has
conclusive evidence, the adapter rereads it on a fresh primary connection. It never
blindly reexecutes a mutation after an uncertain commit. If evidence is missing,
superseded, or inaccessible, `UncertainCommitError` fails closed and the HTTP request
returns a server error. A destructive one-time-code read is an example where absence
alone cannot establish which request consumed it. Availability after that failure is
intentionally secondary to one-use semantics.

| Operation | Conclusive evidence after an uncertain commit |
| --- | --- |
| Owner-code, credential, or client put | The same natural key still holds the exact submitted record. |
| Agent or transaction insertion | Its unique identity still holds the exact submitted record. |
| Key enrollment | The same key and enrollment ID still hold the exact submitted record. |
| Transaction transition | The expected next version and complete resulting record remain; side effects must also be conclusive. |
| Completion | The request's code hash belongs to the completed transaction and expected identity/version. |
| Code redemption | This attempt's marker remains on the used code and its lifecycle/issuance window is still valid; a replay is rejected. |
| Access-token insertion | This request's token hash remains with valid expiry, code, and lifecycle bindings. |
| Other mutations, including destructive owner-code consumption | No recovery claim is made; return `UncertainCommitError`. |

A successful transaction followed by a lost HTTP response can still lose the client's
plaintext authorization code or token. The database stores hashes and this adapter
cannot reconstruct those secrets. This is not an exactly-once delivery guarantee.

## Retention and recovery from backups

Transient data may be removed in indexed bounded batches only after its dependents no
longer need it. Preserve the transaction's original terminal retention window. A used
code is replay evidence while its token remains relevant or its permitted issuance
window remains open; code expiry alone does not permit deletion. Expired reservations
stop counting before physical cleanup. Permanent signup totals and revoked-key records
must survive cleanup.

Call `store.cleanup({ batchSize, retainFor, consentMaxAge })` from a separately
controlled maintenance job. Defaults match the issuer's 300-second transaction
retention and 180-day consent age, with a batch size of 100. Pass the issuer's actual
constants when those settings differ. Reservation candidates and their quota locks
are bounded before deletion; expired key records remain until their transaction
expiry evidence can be retired. Each entity deletion is bounded, although batch size
does not place a hard bound on the query planner's total scanning work. Cleanup has no
authority to extend credential validity.

Restoring an older backup is a security event: it may undo agent/key/credential
revocations, one-use consumption, and disable versions. Keep the issuer offline until
a documented recovery procedure has reapplied revocations and invalidated potentially
revived credentials. Signing-key rotation alone does not invalidate enrolled agent keys
or owner credentials. Test restore procedures and protect backup access as carefully
as the primary database. This adapter does not solve point-in-time security rollback.

## Secret and personal-data storage

Owner/delegated credentials, owner email codes, transaction/session authentication
secrets, authorization codes, and access tokens are stored as hashes. The transaction
`continueSecret` must be returned later in the protocol and is stored in its record in
recoverable form. Owner emails are stored in the owner record, with a lowercase indexed
copy for lookup; names, consent metadata, and request context can also be personal data.

This adapter does not add application-level encryption. Restrict database and backup
roles, encrypt storage/backups, use authenticated TLS, and redact secrets and personal
data from SQL tracing, error reporting, and request logs. Do not expose `data` payloads
or checkpoint query values in diagnostics. Deployments requiring envelope encryption
or keyed email lookup need a separately designed key-management and rotation scheme.

## Operational limits and verification

Defaults: 10 connections, 5-second acquisition and lock timeouts, 10-second statement
timeout, 30-second idle-transaction timeout, and 3 rollback retries (4 attempts total).
Budget the sum of pools across issuer instances against the database connection limit.
Externally supplied pools must have their own bounded acquisition and connection
settings. Share issuer configuration, signing keys, handle domains, and owner-authentication
configuration consistently across instances.

The store contract suite runs on memory, SQLite, and PostgreSQL. PostgreSQL-specific
tests use independent connections and processes, deliberate waits and failures inside
transactions, and a test showing that an unrelated quota pair can proceed while another
pair is locked. Local tests skip cleanly without `AGENTLOGIN_TEST_POSTGRES_URL`; the PostgreSQL CI
job sets `REQUIRE_POSTGRES_TESTS=1`, so missing database configuration fails the job.

These tests establish correctness evidence, not a capacity claim. Dataset-growth
benchmarks, deployment sizing, rate limiting, and production owner sign-in remain
separate work. The RP callback state store is a different interface and package; this
issuer adapter does not make an RP's callback state shared across hosts.
