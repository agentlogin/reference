# Beta operational acceptance

The local rehearsals below establish recovery and failure-handling evidence. They do not configure production
alerts, measure hosted capacity, prove a different replica served a request, or approve opening the beta.
Keep the result of each release beside its source revision and deployment/image digest.

## Reproduce the storage rehearsals

Install the locked dependencies, build the repository, and provide PostgreSQL 17 or later client/server tools.
Use the same tested Node security patch as the candidate release. From the repository root:

```sh
npm ci
npm run build
node --test deploy/pilot/ops/monitor.test.mjs
PG_BIN=/path/to/postgresql/bin node deploy/pilot/ops/run-rehearsal.mjs --output /path/to/new-evidence-directory
```

The runner creates its own loopback-only, trust-authenticated PostgreSQL cluster and empty database, runs tests
serially, and stops/removes the cluster on completion. It accepts no database URL. The outage test intentionally
stops that database: do not attach another task to the temporary cluster. It never accesses production services
or credentials. Interruptions still attempt cleanup; a reported cleanup failure needs operator attention.
The output directory must not exist. Results contain synthetic data and no credentials.

The evidence comprises:

| File | What it proves |
| --- | --- |
| `tests.tap` | Existing store contracts, independent-process session/logout tests, cross-instance callbacks, retry/uncertain-commit behavior and the new drills all passed |
| `restore.json` | A real `pg_dump`/`pg_restore` of an older snapshot demonstrably revives revoked synthetic authority; explicit issuer invalidation, credential removal, callback purge, session purge and secret rotation close the tested paths while preserving notes/counts |
| `signing-rotation.json` | Two PostgreSQL-backed Issuers observe staged keys, preserve routine overlap and refuse signing after emergency withdrawal |
| `outage.json` | Stopping the whole database returns 503 for readiness, protected reads/writes and logout; liveness stays available and acknowledged data survives restart |
| `load.json` | Four workers measure real store reads, polling, completion and revocation at 100, 1,000 and 10,000 seeded historical agents, with p50/p95/p99/max timings and pool bounds |
| `report.json` | Source revision/dirty status, Node/PostgreSQL/hardware, suite exit status and cluster cleanup outcome |

The load drill is a bounded closed workload on local storage. Seeding and warmup are outside timing. It excludes
HTTP, TLS, cryptography, human approval, public networks, cleanup, hot-owner quota contention and production
resource limits; those require hosted measurements. Its measurements must not be presented as supported
requests per second or used to size the beta without headroom and a representative hosted load test.

## Restoration and rollback

Restoration is a security event, not merely a data-import job. Fence public traffic and stop every writer before
restoring. Keep a protected record of the selected backup, its timestamp, post-backup security changes and the
release/schema versions. Reconcile revocations, deletions, ownership generations, consent withdrawal and signup
counts against authoritative history that was not rolled back. When the history is unavailable, quarantine the
affected identities and admissions; do not silently treat a restored mailbox or Owner as current.

Before reopening, invalidate affected Owner and Delegated Credentials, Agent Keys, transactions, authorization
codes and Access Tokens. Purge pending callback state and application sessions; rotate both application secrets
on all replicas. Reconcile SentFrom-specific passkey generations, enrollment requests, verified ownership and
mail claims too: this generic storage drill does not model that separate hosting state. Rotating the Issuer's
signing key alone cannot invalidate restored agent keys, credentials or consumed state. Test a credential known
to have been revoked after the selected backup and require rejection at UserInfo, callback and lasting actions.

For a code-only rollback, restore the previously accepted immutable image while retaining the current database,
revocation state and rotated secrets. Verify the old binary supports the current schema before routing traffic;
the adapters reject unknown schema versions. Never roll back the database or revert secrets merely to make an
old binary start. An incompatible migration requires a prepared forward repair or a full recovery procedure.
The local restart/compatibility tests are not proof that a particular previous production image can roll back.
Record an actual previous-image rehearsal before describing production rollback as verified.

## Monitoring and operational owners

Run the public probe from an independent host, through the same public HTTPS routes as users:

```sh
PILOT_BASE_URL=https://workspace.sentfrom.ai PILOT_ISSUER=https://identity.sentfrom.ai node deploy/pilot/ops/monitor.mjs
```

It bounds response sizes/time, rejects redirects, checks app readiness/metadata/unauthenticated denial and Issuer
metadata/public signing keys, and exits nonzero on failure. It does not sign in, mutate state, or prove delivery
of an alert. Do not log full authentication URLs, headers, bodies, cookies, credentials or raw database errors.

These are proposed beta alert settings until an operator configures and proves them:

| Signal | Initial trigger | Required response |
| --- | --- | --- |
| Independent public probe | Every minute; two consecutive failures | Page the named primary and backup operator |
| Missing probe results | No result for three minutes | Treat as monitoring failure, not service health |
| Database errors/pool exhaustion | Sustained one minute or repeated auth failures | Inspect pool/query health; keep protected operations fail closed |
| Unexpected auth or callback error increase | Compare to measured baseline; investigate repeated replay/Origin failures | Check release and misuse without recording secrets |
| Certificate expiry | Under 14 days | Verify renewal and ownership |
| Backup job or restore validation | Failed backup or missed daily result | Repair before the published recovery objective is breached |
| Resource saturation / latency | Set after hosted workload measurements | Reduce admission or scale within the database connection budget |

Before inviting users, record the primary/backup operators, a support/security address, maintenance authority,
chosen recovery-point/recovery-time objectives, backup retention/access policy, probe location and alert routing.
Send one synthetic failure through the actual alert channel, acknowledge it, restore service and verify the
recovery notice. A green health endpoint or a proposed dashboard is not an alert-delivery test.
Run the authenticated acceptance and dedicated-key revocation drill in `../README.md` against both routed
replicas, without bypassing independent human approval. Capture replica labels, outcomes and release digests.

Protocol basis: [Core Sections 7 and 9](https://github.com/agentlogin/spec/blob/main/agent-login-core.md),
[implementation guide recovery/evidence](https://github.com/agentlogin/spec/blob/main/implementation-guide.md).
Dependency basis: [PostgreSQL consistent dumps](https://www.postgresql.org/docs/current/app-pgdump.html),
[restoration](https://www.postgresql.org/docs/current/backup-dump.html),
[transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html).
