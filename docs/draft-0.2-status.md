# Draft 0.2 compatibility status

This release work list targets specification commit
[`a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78`](https://github.com/agentlogin/spec/tree/a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78).
Discovery's `1.0` value does not distinguish drafts. Pin this revision when assessing
compatibility. This is not an exhaustive conformance report; unlisted requirements
are not automatically passed. Separate AI reviewers are not independent implementers.
The same normative text is now published as [working draft 0.2](https://github.com/agentlogin/spec/releases/tag/draft-0.2)
at `6563b8430b9df1d9a653b44c68b273a5774cabe5`; publication changes only status, date and review documentation.

The implemented product path is direct ES256 sign-in: the PostgreSQL issuer, a
managed Owner integration, the TypeScript client/local MCP helper, and a relying
party with its own shared application sessions and durable notes.

| Area | Implemented behavior and evidence | Remaining boundary |
| --- | --- | --- |
| Authentication age (Core 5.1, 5.6, 5.7) | Issuer/stores/RP preserve `auth_time` and enforce `max_age`, including lock waits, late approval and zero-age freshness. RP token expiry is anchored before the token request and rechecked after validation. | External IdP clock/factor behavior needs deployment verification. |
| Owner verification and approval (Core 6.6, 7.5) | The separate SentFrom.ai identity service implements signed OIDC authentication, immutable user mapping, shared browser state, approval/revocation/reset pages and actual one-time email proof. Email proof does not elevate session authority. | Configure and verify the IdP's independent factor, enrollment and recovery policy; provision its immutable Clerk subject mapping and private email delivery. Reference bootstrap credentials are test/admin facilities, not proof of human authentication. |
| Signing-key lifecycle (Core 7.7) | Durable publication/activation/retirement/compromise state, publish-before-use, shared maximum JWKS cache lifetime, post-signing withdrawal checks and configuration reload. [Tests](../packages/issuer/test/signing-lifecycle.test.ts). | Provision private keys securely and exercise rotation/recovery in the deployment. Non-exportable KMS/HSM signing is not supplied. |
| Address-linked signup accounting (Core 7.6) | Exact local-part/domain-normalized address equality, shared pending capacity, unique Account-creation events, inherited counts, fixed deletion deadlines and published retention policy. [Shared contracts](../packages/issuer/test/store-contract.ts). | Operator chooses the published retention period; zero is permitted. Permanent identity/event records must remain available for their dependent checks. |
| Lifecycle, consent and replay (Core 5-7) | Immutable identities, atomic transitions, preserved polling/retention outcomes, authenticated replay handling and shared callback consumption. SQL lifecycle mutations coordinate with application-originated changes. [PostgreSQL tests](../packages/store-postgres/test/lifecycle-functions.test.ts). | Restore/failover exercises remain operational evidence. |
| Application authorization (Core 9) | Agent Workspace persists private notes, checks UserInfo before a lasting action, and commits session authorization with the write. Idempotency, logout, expiry and bounded pagination have tests. | Other applications implement their own business permissions and sessions. A prior check cannot make arbitrary external side effects atomic. |
| Plugin and catalogs | Local MCP enrollment/sign-in, immutable application-session binding, full disclosure review, configured operations, and optional provider/application catalogs. Catalogs distinguish review evidence from trust, support Open and Registered Clients, and label AgentID separately from Agent Login Core. SentFrom and Agent Workspace candidates now attach [scoped, affiliated live evidence](evidence/2026-10-24-sentfrom-workspace.md). | Both remain candidates pending a recorded catalog review. Historical local-tarball and existing-identity results do not establish new-customer onboarding or publication of the planned beta. AgentID by AgentMail remains an unreviewed OIDC integration candidate, not a Core provider. Inclusion does not grant trust. Browser sessions need their own integration. |
| Algorithms and optional profiles | The release accepts ES256; legacy `EdDSA` configuration is rejected. The harness recognizes optional `Ed25519` naming. | Ed25519, recommended `private_key_jwt`, optional DNS fallback and the separate Relay profile are not implemented by this direct-sign-in release. |
| Rate limits (Core 6.7) | Managed-service shared PostgreSQL limits cover authorization/assertion/Owner requests, with bounded bodies and `429` / `Retry-After`. | Tune edge and tenant limits using measured load and the actual proxy topology. The reference core does not itself impose a deployment policy. |
| Packaging and verification | A clean consumer installs real tarballs without workspace dependency links and runs PostgreSQL sign-in, persistent actions, instance switching, logout and revocation. [Pilot test](../packages/conformance/test/clean-consumer.test.ts). Hosted-service release preparation vendors exact issuer packages into a standalone artifact. | Publishing, actual target deployment, external adopter testing and independent protocol interoperability are not established by local execution. |

See [the review record](product-review.md) for findings and their fixes. Test totals
belong to the final execution report rather than this compatibility table. The
conformance harness remains partial, including checks that cannot be established
through a black-box protocol probe. Passing internal tests is not a 1.0 approval.

Memory and SQLite are local reference/test options. PostgreSQL is the multi-host
release target. The documented SQLite deadline limitation does not justify a
production claim for that adapter.

## External pilot handoff

The clean-consumer test completes the install-and-run part of the pilot locally.
The [dated live SentFrom/Workspace report](evidence/2026-10-24-sentfrom-workspace.md)
adds bounded deployment evidence, using an existing approved identity. Public-beta
installation, a new human participant, and an outside adopter remain required.
Give that adopter the
exact specification revision above, committed package tarballs and lockfiles, the
[application integration guide](../examples/rp-hono/README.md), and the
[helper configuration](../packages/mcp/README.md). Record the tested software
revisions, environment, observations and exclusions without including credentials
or Owner addresses. Do not label a planned check as passed.

| Pilot check | Required observation |
| --- | --- |
| Independent installation | The adopter installs the supplied artifacts without repository links or undocumented dependencies. |
| Live domain discovery | The real handle domain identifies the intended issuer over HTTPS; no loopback or development overrides are used. |
| Human authority | Enrollment and Owner disclosure require the configured independent factor. Agent mailbox/API access alone cannot approve them; factor enrollment and recovery enforce the same separation. |
| Multi-host sign-in and action | Callback completion, session reads and a persistent application action work when routed to different replicas. Logout on one replica denies the session on another. |
| Lifecycle and identity | Key revocation or mailbox suspension blocks a subsequent lasting action. Reset or handle reassignment never exposes the previous subject's application data. |
| Failure and expiry | Expired credentials fail; a lost write acknowledgement can be reconciled using the same operation ID without duplicating an action. Issuer/database outages do not report false success. |
| Upgrade and operations | Actual key rotation, migration, recovery and restore procedures preserve the documented authority and retention boundaries; expected dataset sizes and concurrency are measured. |

These are release acceptance scenarios, not additional Core requirements or a
substitute for its full conformance checklist. Publish only redacted evidence
that its participants approve. A catalog submission may link that report after
the checks actually run; inclusion still does not make an issuer trusted.
