# Product review record

Working evidence for the Agent Login product branch, against specification revision
`a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78`. This records implementation reviews; it is
not independent interoperability, certification or production approval. Reviewers
are separate AI agents, not independent organisations.

## Round 1: boundaries between components

Three reviewers examined components they did not implement: the application and
consumer install, the plugin against the Core, and the hosted Owner/lifecycle bridge.

| Finding | Resolution and evidence |
| --- | --- |
| Note IDs accepted JavaScript coercion | Require a string; HTTP and memory regressions reject numeric and array identifiers. |
| A rejected note left the browser unable to submit corrected text | Validate whitespace before creating a request; discard pending IDs after confirmed validation errors while preserving uncertain writes. |
| The plugin checked a handle without binding the current issuer and subject | Actual issuer discovery now selects the private jar; every action validates the persisted issuer and subject. Regression probes reject former-issuer and replacement-subject sessions. |
| Consent review omitted changed client terms | Bounded client identity, redirect host, terms/privacy URLs and consent reason are displayed before the decision. |
| Owner approval could cross an identity reset | The issuer mutation uses the approved immutable subject and a durable enrollment identifier. A deterministic reset/recreate schedule rejects the old approval. |
| Denying an approved enrollment left key authority intact | Contradictory decisions return conflict; the UI cannot report a denial while leaving approved authority active. |
| Expired enrollment challenges could be reported as approved | Polling reconciles the exact enrollment; an expired challenge requires a fresh request. |
| Changing the issuer schema disconnected lifecycle triggers | Migration records the issuer schema; migration and startup reject an incompatible association. |

## Round 2: lifecycle coordination and integration bounds

Fresh reviewers examined the issuer/storage changes and the integrated plugin,
application, catalog and consumer package boundaries.

| Finding | Resolution and evidence |
| --- | --- |
| READ COMMITTED mail invalidation could race a SERIALIZABLE assertion and leave the wrong terminal outcome/retention | Shared Agent locks coordinate lifecycle authority decisions across isolation levels; deterministic mixed-isolation tests preserve denial and original retention. |
| A newly staged key did not inherit another replica's longer JWKS cache lifetime | Every published key inherits the durable issuer-wide maximum cache lifetime; multi-instance retirement regressions pass. |
| A valid note collection exceeded the plugin's response limit | Notes are paginated into bounded pages below 64 KiB; a regression reads every note across pages without duplicates. Configured GET query parameters support the continuation cursor. |
| JSON escaping made valid 4 KiB notes exceed an 8 KiB request envelope | The envelope is bounded to 32 KiB. Regressions accept maximally escaped valid notes without relaxing the decoded text limit. |

The hosted integration also exposed a mandatory Core 7.5 omission during source
review: the service had no email-code verification method. That method was added separately from strong Owner session authentication; email proof does not
grant enrollment or approval authority.

## Round 3: fresh specification and hosted-service review

Three new reviewers examined the hosted service, issuer authority/accounting, and
actual specification/release contracts. Findings were reproduced before correction.

| Finding | Resolution and evidence |
| --- | --- |
| An expired enrollment could be recreated after its key row was cleaned up | Hosted schema v2 persists the first provisioning deadline; the issuer receives that same deadline. Tests cover cleanup, uncertain insertion, migration and expiry during a wait. |
| Deleting and recreating an Account undercounted lifetime signups | Each Account creation uses its first completion transaction as event identity. Shared tests enforce cap 2 across repeated deletion, inheritance and address changes. |
| Slow RP token validation extended retained Access Token lifetime | Expiry is bounded and anchored before the request; validation delay cannot renew it and an expired result is rejected. Controlled-clock regressions pass. |
| The application catalog excluded opaque Registered Client IDs | Entries now distinguish client types and scope registered IDs by exact issuer. Parser, generated schema, static directory and tests agree. |

Additional integration verification applies every actual SentFrom.ai mail migration
(including pgvector), then enrolls an identity and deletes its mailbox to verify
lifecycle invalidation against the real schema. The working application bounds
request decoding before its live UserInfo check and uses cursor pagination.

## Round 4: new independent security, product and Core reviews

| Finding | Resolution and evidence |
| --- | --- |
| Deleting an Account after assertion bypassed completion-time admission | Completion checks current Account absence regardless of earlier admission state and respects other Agents' pending places. All 195 shared storage contracts passed. |
| Registration silently defaulted a required authentication method | Missing/invalid methods are rejected; I-56 and mutant-issuer tests detect the previous behavior. |
| Repeated unknown authorization parameters were accepted | All merged query/body parameters are checked after client/redirect validation. GET, POST and split-parameter regressions cover JSON and HTML paths. |
| A delayed note save erased a newly edited draft | The browser preserves text changed during the request and prevents overlapping submits. Tests execute the emitted browser script. |
| A list-refresh error encouraged retrying an acknowledged write | Save acknowledgement is separate from refresh failure. Uncertain writes preserve their ID; confirmed writes never ask the user to repeat them. |
| Provider listings accepted query-bearing issuer identifiers | Provider and registered-client issuer validators now share the exact identifier rule. |

## Round 5

Three fresh reviewers checked protocol behavior, hosted identity/plugin boundaries,
and application/release integration. Hosted identity and plugin review found no
further reproducible P1/P2 issues in its stated scope; focused tests passed.

| Finding | Resolution and evidence |
| --- | --- |
| Shared client metadata could change between display and consent acceptance | Public presentation/consent metadata is immutable per transaction; authentication and current policy remain live. Actual Open Client refresh, PostgreSQL JSON absence/addition/removal and bounded legacy cancellation regressions pass. |
| A stale older-page response could overwrite a freshly refreshed note cursor | Generation/cursor-aware handling discards stale successes and failures; emitted-script schedules retain every note without duplicates. |

## Round 6

The delivery review found no reproducible P1/P2 in UI/MCP/catalog/release boundaries;
an additional stale-response browser-script probe passed. The protocol reviewer
verified optional metadata pinning against PostgreSQL JSONB and found one remaining
capacity edge: a sibling transaction whose reservation had already been converted
to an Account could steal another Agent's place after Account deletion.

Both stores now revalidate aggregate capacity for every Account creation, including
transactions with prior reservations. The exact sibling/deletion schedule and a
pending-address-merge case failed before correction on all adapters and pass after.
All 210 shared contracts and six targeted PostgreSQL concurrency tests passed.

## Round 7

The integrated review found that a legacy upgrade could lose the issuance/cache
history needed to keep old signing keys published. Memory/SQLite snapshots and
PostgreSQL v1/v2 upgrades now preserve a durable conservative retirement floor for
the first imported key ring. Failed publication and restart cannot discard it;
compromise withdrawal still overrides ordinary retention.

A proposed quota finding was withdrawn after checking Core 7.6: Account deletion
can leave two competing pending claims above capacity. The specification does not
give either claim priority. Denying the first completion releases only that
transaction's claim; the other can then fit. Both orderings enforce the cap, so no
additional fairness mechanism was added.

## Round 8: independent closure

Two fresh reviewers examined release integration and the final signing migration.
The signing review caught a further edge: continued issuance by an imported legacy
key must extend that key's historical cache overlap. The correction does so without
lengthening unrelated new keys' retention. Twenty targeted tests and an independent
PostgreSQL failed-publication rollback probe passed. No further actionable finding
remained in that review's scope.

The release review found no reproducible P1/P2 in the standalone artifact, dependency
resolutions, CI layout, dashboard authentication boundary, or documentation. It also
checked the external pilot handoff against the actual Core. Release verification
additionally requires the full suite with PostgreSQL required, a committed reference
pin in the hosted service, and installation of the artifact built from clean commits.

These reviews checked the actual pinned Agent Login Core and applicable primary
upstream material, including [OpenID Connect key rotation](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
and [PostgreSQL transaction isolation](https://www.postgresql.org/docs/17/transaction-iso.html).
Publication, deployment and external adoption are not inferred from internal
reviews or tests. No review can establish the absence of every possible defect.
