# Agent Login trusted providers

**Draft programme. No provider is approved by this document.**

A website can choose the named Agent Login provider policy once and receive its
reviewed additions, suspensions and removals through policy updates. Individual
people and agents are not asked to adopt the list during sign-in. A website can
instead choose its own issuers or maintain its own policy.

This is an optional acceptance policy, not part of Agent Login Core. Core remains
open to any conforming issuer. Neither installing an SDK nor implementing Core
subscribes a website to this programme. The reference implementation has no
implicit default registry, consistent with the specification's
[governance](https://github.com/agentlogin/spec/blob/main/GOVERNANCE.md).

The programme is not operational until its accountable operator, adopted policy,
authenticated publication and recovery arrangements, and first completed provider
decision are published. Reviews and admission decisions may be automated under
the operator's published delegation. Automated or affiliated review does not
establish independent endorsement.

## What websites are choosing

Choosing this policy delegates a bounded decision: which identity issuers may
establish new Agent Login sessions. Updates may add providers without another
website approval. The website operator must be told this when selecting the
policy. Websites retain their own deny rules and can stop following updates.
Changing to a different programme, publication origin or policy scope needs a
separate operator decision; a feed cannot grant itself that authority.

A listing means that a named operator met the documented admission criteria for
an exact issuer, domain scope and protocol revision, within the stated review
period. It does not guarantee service availability, honest agent behaviour,
unique humans, permission to spend money or access data, or suitability for every
application. Each website still controls accounts, permissions, quotas and
application sessions. Websites do not need to join the list to use the sign-in
button.

The existing [participant catalog](../catalogs/README.md) is a discovery directory,
not this approval policy. Its `candidate` and `reviewed` labels do not grant
membership. SentFrom.ai and AgentID by AgentMail remain catalog candidates. Hark,
Muse and other prospective providers receive no status merely by being named in
a discussion. SentFrom.ai receives the same review as any other applicant.

## First programme scope

The first programme covers direct issuers implementing
[Agent Login Core](https://github.com/agentlogin/spec/blob/main/agent-login-core.md).
Each approval identifies the immutable specification commit reviewed, the exact
HTTPS Issuer Identifier and explicitly reviewed handle domains. It does not
approve an organisation's other services, future domains, aliases or a replacement
issuer. Programme admission review establishes compatibility with the named
profile; the pinned specification commit records what was reviewed, not a claim
that a client can understand every possible commit.

Relays and their upstream trust policies need a separate review profile and are
outside this first programme. AgentID is a separate protocol integration; its
catalog entry and adapter do not establish Core compatibility or membership here.
An agent host can use an admitted issuer without operating an issuer itself.

Listing checks supplement Core validation. Websites still perform domain
resolution and handle binding, issuer and token validation, PKCE, callback state
and replay protection, and the other applicable Core requirements. A list cannot
redirect discovery, merge accounts between issuers or override a domain's current
delegation. Account identity remains `(iss, sub)`.

## Admission evidence

An application contains the following evidence. Reports identify the responsible
organisation or maintainer, affiliations, observation date, review method and tool
versions, tested source revision, exact specification commit, reproduction steps,
results, exclusions and expiry. Evidence is public or has a public summary
explaining any confidential portion; secrets and Owner personal data do not belong
in the application.

| Area | Required evidence |
| --- | --- |
| Accountable operator | Public operator identity, control of the issuer and each proposed handle domain, and working security and operational contacts. |
| Protocol behaviour | Completed applicable Core checklist with evidence for each conclusion, reproducible positive and negative tests, and an end-to-end run against a separately maintained relying party or client. Skips and unresolved deviations are explicit. |
| Owner authority | Review of first enrollment, approval, recovery and administrator overrides demonstrating that an agent cannot obtain or exercise the Owner's approval factor. Email verification or a method label alone is insufficient. |
| Identity and lifecycle | Tests for immutable identity, re-created handles, key enrollment/revocation, disable/re-enable, code and assertion replay, consent changes and concurrent quota enforcement. |
| Operations | Rate limits, abuse reporting, key protection and rotation, monitoring, incident response, and a recovery rehearsal that prevents restored backups from reviving revoked authority. |
| Privacy and terms | Public operator policy covering collected and disclosed data, deletion and retention, applicable signup-count linkage, and material-change notifications. |

Admission requires no unresolved defect that can permit identity substitution,
unauthorised Owner approval, disclosure or account access. A passing harness alone
does not establish admission or full conformance. Reviewers assess untested
requirements and document the basis for their conclusions. Automated or affiliated
review, including a provider reviewing its own application, may support a decision
under the same published criteria. Disclose that relationship and do not describe
it as independent approval.

Admission is scoped, time-limited and renewable. The decision's expiry cannot be
later than any evidence on which it relies. Material changes to ownership,
security controls, recovery, deployed protocol behaviour or the approved domain
scope require reassessment before the changed deployment relies on that approval.
An issuer URL change is a new identity and a new application, not a feed edit that
silently transfers existing approval.

## Decisions and accountability

Before launch, publish the accountable programme operator and responsible
maintainers, their affiliations, roles and authenticated decision channels. An
organisation can hold these responsibilities; named individual people are not
required. Publish the programme version, review criteria and any delegation to
automated reviewers or decision systems, including their authority and limits.

Admission and reinstatement require a completed evidence-based decision under
those criteria. No human approval, reviewer count or external quorum is required.
The programme operator remains accountable for delegated decisions. Disclose
employment, ownership, financial interests and other affiliations with an
applicant. Affiliated review is permitted under the same criteria, including for
the operator's own provider; it is not independent endorsement.

Every admission, rejection, renewal, suspension, withdrawal and reinstatement has
a dated public [decision record](decision-template.md). It links the application,
evidence, conflicts, exact scope, reasons, responsible decision authority, review
method, validity period and resulting policy revision. Automated decisions record
the system and tool versions, tested source revision and test results.
Authenticated publication identifies the publisher; it does not replace the
underlying review. Distinguish automated from manual assessment and vendor evidence
from independently produced evidence.

Programme rule changes are published with their rationale and an authenticated
adoption decision by the accountable operator or its published delegate. Expanding
beyond direct Core issuers or changing the subscription's trust root creates a new
policy choice for websites. These programme decisions do not amend the Core
specification or bypass its separate governance. Admission cannot be purchased or
exchanged for partnerships.

An applicant can request correction or appeal with new evidence. The programme
operator or its delegate reassesses the disputed findings and publishes the
method, affiliations and reasoning, including whether the original reviewer or
system was reused. An appeal does not restore acceptance while its subject is
suspended or expired.

## Status, renewal and incident response

| Programme status | Consequence for the approval policy |
| --- | --- |
| Applicant | No acceptance; application is under review. |
| Approved | Accepted only for its recorded scope while the policy and evidence remain valid. |
| Suspended | New sign-ins are refused once the suspension update is applied. |
| Withdrawn | No acceptance; the prior decision remains in the public history. |
| Expired | No acceptance when the approval or required evidence has expired, even if a status label still says approved. |

Keep the original expiry if a renewal is incomplete. Do not extend validity simply
because an incident is being investigated or a feed is unavailable. Reinstatement
requires evidence of remediation and a new decision; it is never inferred from a
provider returning to a healthy HTTP response.

The operator or its authorised delegate, including an automated system, can
suspend a provider immediately on a credible threat to identity or Owner authority.
Record the acting authority, method, time, affected issuer and reason; reassess the
evidence promptly and publish the outcome. Publish sensitive technical details only
when that will not worsen the incident. Contact
the provider's security contact, publish a redacted incident notice, and preserve
the decision history. Suspension does not require the provider's permission.

A website can block an issuer locally before a programme update arrives. Provider
suspension is not a claim that all existing application sessions are remotely
revoked: the website owns those sessions. Its incident procedure must identify
sessions by issuer, apply local restrictions or invalidate them where appropriate,
and preserve Core's UserInfo rechecks before actions with lasting effects.

## SDK integration (beta.3)

The helper is part of `0.2.0-beta.3`. Check the [release status](../docs/npm-release.md)
before installing it from npm. SDK publication does not activate this programme.
Its explicit opt-in is:

```ts
import { RelyingParty, agentLoginTrustedProviders } from '@agentlogin/rp';

const rp = new RelyingParty({
  clientId: 'https://app.example.org/client-metadata.json',
  redirectUri: 'https://app.example.org/auth/agent/callback',
  issuers: [],
  issuerPolicy: agentLoginTrustedProviders(),
  stateSecret: process.env.STATE_SECRET!,
});
```

Keep the [RP integration's](../packages/rp/README.md) shared callback store, account
mapping and application sessions. An empty `issuers` array allows the selected
policy to supply approved issuers; it does not mean accept every issuer. Explicit
issuer entries can supply credentials for that exact issuer, but cannot bypass the
policy. Top-level credentials, accept-any federation and Relays are incompatible
with this helper. Present a handle before any request to the issuer: both the
discovered issuer and its handle domain must be approved. The bound requested
handle is preserved for live checks even when the granted scopes omit `email`.
Domain discovery and token validation still apply.

The [draft feed](v1.json) accepts no providers. It is not an active approval
policy, so this configuration cannot yet be used as a
working public sign-in service. Keep an existing explicitly configured issuer
policy until the programme is operational; do not configure an automatic fallback
that bypasses this policy on errors.

## Publication and consumption

The helper's fixed HTTPS endpoint is
`https://agentlogin.github.io/reference/trusted-providers/v1.json`. Publication is
trusted through that exact origin and HTTPS certificate validation. Version 1 is
not independently JWS-signed: repository publishing access, CI and hosting are part
of the trust root. Before activation, publish the responsible maintainers, controls
on publishing authority, incident response and recovery process. A compromised
publisher or host can grant issuer acceptance; an HTTPS fetch alone does not detect
that compromise. A future signing scheme would need separately trusted keys and
an explicit migration, not keys supplied by an unverified feed.

The release identifies `programme: "agentlogin-trusted-providers"`, format
`version: 1`, the fixed profile
`"agent-login-core-1.0-draft-0.2-direct-es256"`, `status: "draft"` or `"active"`, a
positive integer `revision`, `issuedAt`, `expiresAt`, and `providers`. Each approved
provider supplies its exact `issuer`, `handleDomains`, public `reviewUrl`,
`reviewExpiresAt` and `specRevision`. The last field is the reviewed specification
commit as 40 lower-case hexadecimal characters: an audit pin, not a runtime claim
that every commit is understood. Only admissions belong in `providers`; suspension
or withdrawal removes that issuer. Public historical decisions stay available
separately. A draft has no approved entries.

Unknown profiles are rejected. This feed cannot silently add AgentID, Relays or an
incompatible Core expansion. The current runtime still checks Core metadata,
protocol version, signing algorithm and token claims; the programme review
establishes that each provider meets this profile at its recorded revision. A
future incompatible profile requires a client update and a separate website
operator choice.

The client limits responses to 64 KiB and 100 provider entries, fetches for at most
10 seconds, and allows neither redirects nor private-address destinations. A
release is valid for at most 24 hours and an individual approval only until its
review expiry. Publication must renew releases before their expiry; rebuilding an
expired draft does not approve any provider. Every sign-in rechecks absolute
expiry. A locally cached release can be used for at most 60 seconds before refresh; a
failed refresh refuses sign-in with HTTP 503 instead of using stale data.
Refresh requests send `Cache-Control: no-cache` to request revalidation, but HTTP
request directives are advisory. An origin or intermediary cache can still return
an older, unexpired release; neither its `Date` nor `Age` proves that it contains
the latest programme decision. These headers cannot extend the body's original
expiry. See [RFC 9111 Sections 5.1 and 5.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1).

Consumers validate the whole release before replacing the previous one. Invalid,
unsupported or expired releases cannot add authority. Never fall back to the
catalog, accept-all mode or an expired release. Each running helper rejects older
revisions, but this first implementation does not persist the highest revision
across process restarts or coordinate it between hosts. After a restart, an
otherwise valid older release can therefore be accepted until its original expiry,
within the 24-hour maximum. Applications requiring durable rollback protection
need a separately reviewed persistent policy-distribution layer; this helper does
not claim to provide one.

Rechecking acceptance before sign-in completion prevents a started request from
bypassing a suspension already applied to that process. Suspension is not globally
instant: the local cache can add up to 60 seconds, while publication, origin/CDN
propagation and network delays add to that window. The restart limitation above
also applies. There is no guarantee of worldwide suspension within 60 seconds.
The website should monitor refresh/expiry failures and record applied revisions
without unnecessarily logging tokens, handles or Owner data. Its local issuer
blocks take precedence.

The programme remains a draft: no production admission, operational publishing
schedule or accountable operator roster is asserted here. Repository test fixtures
are not approvals. Activation requires completed decision records, separately
exercised publication and recovery controls, and tests for malformed and expired
releases, partial updates, concurrent refresh, rollback, cold starts, restarts, and
a suspended issuer's in-flight callback.
