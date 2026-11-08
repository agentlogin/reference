# SentFrom.ai provider application

**Evidence application, 8 November 2026. This document does not grant admission.**
The authenticated decision history and current policy feed determine acceptance.
These observations expire on **23 November 2026 at 00:00 UTC**, or earlier after
a material change. New observations do not reset the dates of historical tests.

| Scope | Value |
| --- | --- |
| Operator | Brightboard AI Ltd, trading as SentFromAI; [public terms](https://sentfrom.ai/terms). |
| Issuer | `https://identity.sentfrom.ai` |
| Handle domain | `mail.sentfrom.ai` only |
| Profile | `agent-login-core-1.0-draft-0.2-direct-es256` |
| Specification | [`536c5d15738f45a3c2115884a0a43cdd28b06dd3`](https://github.com/agentlogin/spec/tree/536c5d15738f45a3c2115884a0a43cdd28b06dd3) |
| Identity source | [`074175e59ae269be3135c4d865d7bca13dd34e73`](https://github.com/samuelar2/sentfromai/tree/074175e59ae269be3135c4d865d7bca13dd34e73/packages/identity) |
| Issuer/store source | [`62c54330cca22a1ff0a61c4278431ca23457926d`](https://github.com/agentlogin/reference/tree/62c54330cca22a1ff0a61c4278431ca23457926d) |
| Contact | [support@sentfrom.ai](mailto:support@sentfrom.ai) for operations, security and corrections. |

The identity service is an invited-Owner pilot. Programme membership would not
make onboarding unrestricted or establish capacity, availability or a general
production-readiness certification. Other SentFrom services, custom domains,
Relays and AgentMail AgentID are outside this application.

## Review method and affiliation

Prepared for the operator using Codex, source inspection, recorded test receipts,
fresh public HTTPS checks and authenticated deployment-metadata readback.
Separate review agents checked the admission mapping, recovery binding and
publication machinery. They are automated reviewers within this project, not
independent organisations. SentFromAI operates this provider, the programme,
reference implementation and counterpart application. That affiliation is
disclosed, not treated as independent endorsement.

Tests used Node 22.23.4, TypeScript 5.9.3, PostgreSQL 17 in release CI and
PostgreSQL 18.6 in the identified local adversarial/recovery exercises. Synthetic
authenticators prove server checks; they are not represented as human ceremonies.
The public summaries omit credentials, Owner identifiers, fingerprints, private
handles and live approval links. Original restricted receipts remain with the
operator for audit.

## Operator and domain control

The operator's authenticated Railway readback on 8 November identifies the same
two-replica identity deployment and image tested on 3 November:
`sha256:565902de80eca62f7708d43dd5a5165e0baafbd8797c73e09700482ac0f83aea`.
The original deployment receipt binds all 48 artifact files to the source above.
This establishes deployment control in the operator account, not independently
verified legal identity or control of unrelated domains.

Fresh anonymous HTTPS reads on 8 November confirmed the exact issuer, ES256,
Core version `1.0`, and the single advertised handle domain. Metadata SHA-256:
`3edc727981c3ffe2725192bd54691d948b03711371919b18259ba8b15e08b79f`.
A synthetic, unregistered `mail.sentfrom.ai` WebFinger request returned a `302`
to the same resource on `identity.sentfrom.ai`; no redirect was followed. This
corroborates the previously deployed and inspected Cloudflare delegation. The
actual enrolled pilot's domain discovery was exercised in the historical live
run below. These observations do not assert that an arbitrary handle exists.

The operator selected the contact above and confirmed receipt of a labelled
monitor test. It does not establish 24-hour staffing or a response-time guarantee.
Accountability and escalation are defined in [the programme operator record](../../OPERATOR.md).

## Protocol, Owner authority and lifecycle

The [57-item issuer checklist](issuer-checklist.md) records test, source-review
and deployment evidence separately. The [release CI](https://github.com/agentlogin/reference/actions/runs/42321226646)
passed 970 top-level tests with no failures or skips. Its issuer and PostgreSQL
source and test trees are unchanged from the deployed reference revision.
Some black-box harness subchecks need source assessment; the checklist states
those limits instead of claiming 57 exhaustive live passes.

The [October pilot report](../../../docs/evidence/2026-10-24-sentfrom-workspace.md)
records actual human passkey activation, subsequent Owner-approved Agent Key
enrollment, proof of possession and live sign-in. The restricted activation
receipt records full-fingerprint and generation matching, independent device and
recovery-control confirmation, and no Owner session fabricated by activation.
Later server/HTTP exercises cover fresh verification, UP/UV, origin/RP ID,
challenge and signature validation, replay, recovery, administrator generations
and replica races. Current identity authority source is unchanged from those
tests. A fresh second-account usability test remains a separate launch task.

Mapped lifecycle tests cover recreated handles, immutable identity, exclusive
enrollment, immediate revocation, disable/re-enable, unchanged terminal retention,
changed-term consent and concurrent quota accounting. Nine additional HTTP tests
on memory, SQLite and PostgreSQL confirm that a used code replayed with a wrong
PKCE proof, client or redirect does not revoke the legitimate token; a correctly
bound replay does. They use two issuer instances and no production credentials.

## Interoperability

[Agent Tasks](https://github.com/agentlogin/agent-tasks) is a separately maintained
application/repository, release and database. It uses the shared RP SDK and the
same operator, so it is not an independent protocol implementation. Its
2 November live run, at application source
`1f56ad5d371616981b6d2b803c0ebe54d901efc6`, passed ten checks covering binding,
task creation/readback, idempotency/conflict, process replacement, completion,
replay and logout. A separate receipt attributed 11 successful authenticated
requests and six post-logout old-cookie refusals to both replicas. The later
identity deployment passed another existing-pilot sign-in/logout check.

## Operations, recovery and privacy

The deployed identity host uses shared PostgreSQL rate buckets for authorization,
assertion and Owner operations, with `429` and `Retry-After`. Limits use the
observed network source; no per-human fairness or measured public capacity is
claimed. Operator credentials are separate from runtime credentials and must
never be available to a customer agent. Signing configuration is versioned and
validated; signing lifecycle tests cover publish-before-use, overlap, fixed key
identities and emergency withdrawal. Rotating a mail-service AWS key is not an
issuer signing-key operation.

The [recovery report](recovery-report.md) binds the exercised rollback/quarantine
procedure to all 42 first-party runtime modules in the deployed artifact.
The operator's [recovery procedure](recovery-procedure.md) requires authority and
admission to remain closed when post-backup security history is missing. This
does not claim a production restore, safe automatic reopening, scheduled-snapshot
integrity, attachment recovery or an RTO/RPO.

The [identity data disclosure](identity-data.md), general privacy policy and
terms cover scopes, sign-in visibility, deletion, retention and material changes.
The live [quota policy](https://identity.sentfrom.ai/policy), read on 8 November,
explicitly sets post-Owner-deletion address linkage to zero seconds. Its SHA-256
is `086967e39b0a7613f1f68d1d2881dd50e08acc6669a75e170bad55d685f501ec`.
Zero quota linkage does not mean immediate erasure of every security or backup
record, and no previous identity or consent is inherited.

No unresolved identity-substitution, unauthorised-Owner-approval or disclosure
defect was identified in this scoped review. That is a conclusion from the mapped
evidence, not a claim that testing proves the absence of every defect. A decision
must retain these limits and require reassessment after material changes.
