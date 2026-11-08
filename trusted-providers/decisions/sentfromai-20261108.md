# SentFrom.ai initial admission

**Prepared 8 November 2026. Effective only through an authenticated, verified
active policy release containing this decision.** The machine-readable decision
records the exact decision time and expiry. An application, draft page or passing
test suite alone does not activate this admission.

| Decision field | Scope |
| --- | --- |
| Decision ID | `sentfromai-20261108-admit` |
| Action | Admit |
| Programme | `agentlogin-trusted-providers`, version 1 |
| Decision authority | `sentfromai-programme-maintainers`, acting for Brightboard AI Ltd, trading as SentFromAI |
| Issuer | `https://identity.sentfrom.ai` |
| Handle domains | `mail.sentfrom.ai` only |
| Profile | `agent-login-core-1.0-draft-0.2-direct-es256` |
| Specification | `536c5d15738f45a3c2115884a0a43cdd28b06dd3` |
| Tested identity source | `074175e59ae269be3135c4d865d7bca13dd34e73` |
| Tested issuer/store source | `62c54330cca22a1ff0a61c4278431ca23457926d` |
| Previous decision | None |
| Approval deadline | 15 November 2026, 00:00 UTC; never extended by feed renewal |
| Earliest historical evidence deadline | 23 November 2026, 00:00 UTC |
| Initial policy revision | 2; later feed revisions retain this approval deadline unless a new decision is issued |

## Basis

The applicable [programme criteria](../README.md#admission-evidence) are assessed
in the [application](../applications/sentfromai/README.md). Its complete
[issuer checklist](../applications/sentfromai/issuer-checklist.md) distinguishes
executed tests, live observations and source review. Historical observations keep
their real dates. This decision accepts the stated source assessments and coverage
limits; it does not turn an unexecuted probe into a passing live test.

| Area | Conclusion and evidence |
| --- | --- |
| Operator | The public operator and contact are identified; authenticated deployment control, current issuer metadata and domain delegation corroborate the exact scope. Legal identity is an operator assertion, not a third-party verification. |
| Protocol | The complete applicable checklist is mapped. The 970-test release suite covers unchanged deployed issuer/store source; Agent Tasks supplies a separately maintained, affiliated application counterpart. |
| Owner authority | Actual pilot factor activation and key approval complement the server, HTTP and database tests. Clerk or email access alone cannot activate the approval factor. Privileged operator recovery remains a trusted, separately controlled boundary. |
| Lifecycle | Adversarial tests cover identity replacement, enrollment, revocation, replay, consent, retention and quotas. Nine additional used-code replay tests directly protect the legitimate token from incorrectly bound replays. |
| Operations | The application records rate limiting, signing-key controls and monitoring limitations. The bound recovery rehearsal demonstrates restored-authority quarantine. The adopted recovery procedure keeps affected authority and admission closed when history is insufficient. |
| Privacy | The public identity disclosure explains granted scopes, sign-in visibility, deletion and retention. The live quota policy explicitly uses zero post-deletion address linkage; identity and consent are never inherited. |

No unresolved defect permitting identity substitution, unauthorised Owner
approval, disclosure or account access was identified in the assessed scope.
This is an evidence-based, time-limited conclusion, not proof that no defect can
exist. The current issuer remains an invited-Owner pilot. Admission does not
certify general launch readiness, availability, capacity, agent behaviour or
the safety of an application's permissions.

## Authority, method and affiliation

The operator authorised programme implementation and evidence-based admission.
The [operator record](../OPERATOR.md) identifies responsibility and the limits of
delegated automation. This assessment used Codex-assisted source review,
independent agent review passes, pinned CI results and bounded current checks.
The application records tool versions, source revisions, dates and exclusions.

This is affiliated self-review: SentFromAI also operates the programme, the
reference implementation and Agent Tasks. Review agents are not independent
organisations, and shared SDK use is not independent protocol implementation.
No human reviewer quorum or outside endorsement is asserted or required.
Authenticated source publication records the decision authority; it does not
replace the underlying evidence.

## Conditions and follow-up

The operator adopts the [issuer recovery procedure](../applications/sentfromai/recovery-procedure.md)
for the bound deployment. If acknowledged revocations, deletions, ownership or
signup history cannot be reconstructed after a restore, uncertain authority and
admission stay closed. A successful restore or a fresh enrollment alone cannot
authorise reopening. No production restore or guaranteed RTO/RPO is claimed.

The [publication procedure](../ACTIVE-PUBLICATION.md) governs renewal, expiry,
suspension and recovery. Source decisions are pending until their authenticated
release is published; CDN and client-cache delays remain explicit. Websites may
block an issuer locally and remain responsible for their existing sessions.
The first active publication must pass its exact-byte and SDK checks. A failed
deployment may retry only the exact still-current verified artifact, or prepare
a higher revision; never restore older acceptance history.

The programme operator owns renewal before 15 November. Material changes to
ownership, domain scope, Owner factors or recovery, signing/identity controls,
deployed protocol behaviour or the reviewed data policy require reassessment
before relying on this approval. A new issuer URL requires a new application.
An expiry, suspension or withdrawal removes acceptance; a healthy endpoint alone
does not reinstate it.

Fresh-account onboarding remains a separate joint acceptance test with the user.
There is no claim that an agent completed a person's device prompt. Mail-service
attachment recovery and broader staffing/launch commitments remain outside this
limited issuer admission, except where they affect its authority guarantees.
Security reports and corrections go to [support@sentfrom.ai](mailto:support@sentfrom.ai);
public corrections can use the repository's issue tracker. Sensitive evidence
must not be posted publicly. Superseding decisions append to the public history.
