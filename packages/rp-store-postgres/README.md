# PostgreSQL RP callback store

`@agentlogin/rp-store-postgres` implements `CallbackStateStore` from `@agentlogin/rp` for applications running on
several hosts. Login can start on one replica and return to another; concurrent callbacks compete for one durable
claim before either can exchange the authorization code. PostgreSQL 17 is exercised by the integration suite.

This is separate from the issuer's `@agentlogin/store-postgres`. The callback table contains only opaque HMAC
state digests, expiry times and consumption flags. Pending cookies, PKCE verifiers, authorization codes, issuer
records, application accounts and application sessions are not stored here. The
[Hono example](../../examples/rp-hono/README.md) demonstrates separate PostgreSQL account and session tables, using
the same bounded connection pool while keeping callback and session lifecycles independent.

```ts
import { createHandlers, RelyingParty } from '@agentlogin/rp';
import { PostgresCallbackStateStore } from '@agentlogin/rp-store-postgres';

const callbackStore = new PostgresCallbackStateStore({
  connectionString: process.env.RP_DATABASE_URL!,
  schema: 'agentlogin_rp', // Optional; this is the default.
});
await callbackStore.verifySchema(); // Migrate separately before serving requests.
const rp = new RelyingParty({
  clientId: 'https://app.example/client-metadata.json',
  redirectUri: 'https://app.example/auth/agent/callback',
  issuers: ['https://issuer.example'],
  stateSecret: process.env.STATE_SECRET!, // Stable and shared by every application replica.
});
const auth = createHandlers(rp, { callbackStore, onSignIn });
// Wire auth.login and auth.callback to your framework; onSignIn creates your application session.
// Periodically await callbackStore.cleanup(1000).
// Drain requests and maintenance jobs, then await callbackStore.close() at shutdown.
```

## Setup and connection ownership

The installed package provides `agentlogin-rp-migrate`; in this repository run `npm run rp:migrate`. Both require
`RP_DATABASE_URL` and accept `RP_DATABASE_SCHEMA` (default `agentlogin_rp`). Run migrations with a deployment role;
normal application startup calls `verifySchema()` and ordinary operations perform no DDL. The programmatic
equivalent for migration tooling is `await callbackStore.migrate()`.

Schema names are lowercase SQL identifiers of at most 63 characters and cannot begin with `pg_`. Migrations are
transactional and use a migration-only advisory lock; request operations do not take that lock.

Use a dedicated schema and a runtime role limited to the schema usage, table DML, metadata reads and clock
function execution it needs. Keep schema creation and alteration privileges with the migration role. Verify the
schema before exposing the application to traffic, and do not change it underneath a running incompatible version.

Supply exactly one of `connectionString` or an externally configured `pg.Pool` as `pool`. An external pool is
useful for custom authenticated TLS, observability and connection policy; its caller owns and closes it. The
adapter closes only pools it creates. Its own pool defaults to ten connections; budget the sum of replica pools
against PostgreSQL's connection limit. External pools need bounded acquisition and connection timeouts too.
Use the authoritative primary, not a read replica or cache, for every callback operation.

Defaults are five seconds for connection acquisition and lock waits, ten seconds per statement and thirty seconds
for idle transactions. Configure them through `connectionTimeoutMs`, `lockTimeoutMs`, `statementTimeoutMs` and
`idleTransactionTimeoutMs`; `maxConnections` sets the owned pool's size. External pools retain their own connection
settings. `onPoolError` can report idle connection failures; redact driver errors before logging them.

## Registration, claims and time

`register(key, expiresAt)` accepts the opaque digest supplied by the RP handlers and an absolute Unix timestamp in
milliseconds. It inserts only if the key is absent; `false` means an existing record was preserved, whether used,
unused or expired but not yet cleaned up. Reusing a key never renews its stored expiry or resets its consumption.

`claim(key)` returns `claimed` to one request, `duplicate` for a live consumed record, or `missing` when absent or
expired. It acquires the table lock needed for a write and locks that callback row, reads the database clock after
those waits, and changes an unused live row to used in the same transaction. The table lock is compatible with
ordinary readers and writers; other keys can proceed independently. No network request to an issuer or
application callback runs while that transaction is open.

The adapter uses `READ COMMITTED` with an explicit row lock and one checked-out connection per transaction, as
described by [PostgreSQL row locking](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS) and
[node-postgres transactions](https://node-postgres.com/features/transactions). Expiry uses a SQL wrapper around
[`clock_timestamp()`](https://www.postgresql.org/docs/17/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT),
which advances during a transaction. A timestamp captured before a lock wait cannot authorize a late claim.

The RP handlers choose the pending cookie's expiry using the application's clock; the database enforces the
registered deadline with its clock. Keep both synchronized and monitor clock drift. The test suite changes the
clock function only inside disposable schemas; production requests cannot supply a replacement clock.

## Failures and retention

The adapter does not automatically retry operations. Errors fail closed: the handlers return `state_store_failed`
without exchanging a code. An uncertain commit discards the connection; it never turns a later reread of
`used` into proof that this request won. After an uncertain claim or token exchange, start a new sign-in. Never
release a claim after token validation or session creation fails.

Call `cleanup(limit)` from controlled maintenance, with a default batch of 1,000 and a maximum of 10,000 rows.
Cleanup uses the expiry index and skips locked records; it deletes only expired records and does not make expiry
effective. Overlapping jobs are safe, but avoid scheduling more database work than your deployment needs. Monitor
retained rows and increase maintenance frequency when sign-in volume outgrows the deletion rate. Never evict live
records to reclaim space.

Acknowledged claims must survive failover. Configure PostgreSQL durability and replication to preserve them before
another primary serves callbacks; this adapter cannot repair a database rollback. Restoring older data can restore
an unused state whose code was already exchanged. Before serving traffic after a restore or any failover that
might lose acknowledged claims, rotate `stateSecret` across every replica and reject cookies using the old secret.
Do not keep the old secret as a decryption fallback. This ends pending sign-ins; it does not replace application
session recovery. Protect database access, backups and TLS credentials, and do not log pending cookies or secrets.

## Protocol boundary and tests

[Core Section 5.7](https://github.com/agentlogin/spec/blob/main/agent-login-core.md#57-id-token-validation) requires
response and session/issuer validation before state consumption and keeps state consumed after a failed or
uncertain exchange. It recommends atomic coordination across serving instances; this adapter provides that
coordination for the existing handlers. The store does not replace their PKCE, nonce or issuer checks. Those
checks follow [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1) and
[RFC 9207 Section 2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4).

Run `npm test` for the repository suite or `npm run test:postgres` for both PostgreSQL packages. Database tests use
the explicit `AGENTLOGIN_TEST_POSTGRES_URL`, isolate their schemas, and skip when it is absent. Set
`REQUIRE_POSTGRES_TESTS=1` to fail on missing configuration, as CI does. Concurrency and failure tests provide
correctness evidence; they do not establish deployment capacity. Load testing, application session policy,
rate limiting and operational recovery remain application responsibilities. The Hono example supplies shared
session storage; other applications may integrate their existing session system.
