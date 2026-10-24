# Participant catalogs

These optional public lists separate identity **providers** from **applications**
that accept Agent Login. Provider records explicitly distinguish Agent Login Core
from separately supported AgentID OIDC integration. They are discovery aids, not a
central root of trust, certification program or protocol requirement. For Core,
domain discovery identifies an issuer; each relying party decides which issuers it
accepts. The open specification has no default provider, registry or relay.

The [provider catalog](providers.json) lists SentFrom.ai as a candidate with issuer
`https://identity.sentfrom.ai` and handle domain `mail.sentfrom.ai`. The
[application catalog](applications.json) lists Agent Workspace as an Open Client
candidate. Both link [dated, redacted deployment and scoped sign-in evidence](../docs/evidence/2026-10-24-sentfrom-workspace.md).
The report is an affiliated, Codex-assisted self-report, with historical package
versions and explicit exclusions. Both entries remain candidates pending a recorded
review decision; evidence attachment alone does not promote them to `reviewed`.

[AgentID by AgentMail](https://www.agentid.com) is also an unreviewed candidate,
identified as `protocol: "agentid"`, with issuer `https://auth.agentid.com` and the
documented default inbox domain `agentmail.to`. Its
[sign-in documentation](https://docs.agentmail.to/agentid-sign-in) describes a
separate integration; this listing makes no Agent Login Core compatibility claim.
It requires an AgentID OIDC connection, not the Core RP SDK. The separate
[AgentID MCP adapter](../packages/agentid-mcp/README.md) connects configured apps
through AgentMail's documented API and hands completion to the browser. Catalog
records do not configure or authorize that adapter. The listed domain is a limited
catalog entry, not a claim that AgentMail supports no other inbox domains; see its
[inbox documentation](https://docs.agentmail.to/inboxes).

Adding a candidate does not make it automatically trusted or accepted by any
application. Website developers choose providers and configure an acceptance
policy during integration; the sign-in button does not ask end users to adopt this
directory. There is no automatic subscription to its entries. Anyone can host a
copy or maintain a different acceptance policy.

## Submission and review

Submit a pull request containing the operator's identity/contact page, exact issuer
or client identifier (and its registering issuer for a Registered Client), supported
handle domains or initiation URI, and the protocol. Core records identify the
40-character specification commit being implemented; AgentID provider records
identify the official documentation URL in `protocolReference` instead. A reviewer
checks control of the named domain and attaches reproducible protocol test evidence
for the specified protocol and revision or reference.
Evidence records identify the reviewer, observation date, expiry date and public URL.
Do not include credentials, personal Owner addresses or raw security artifacts.

Status has a narrow meaning:

| Status | Meaning |
| --- | --- |
| `candidate` | Submitted information; no review conclusion |
| `reviewed` | Domain-control and protocol-test evidence supplied for the listed protocol and revision or reference |
| `suspended` | Listing retained for audit, currently unsuitable for recommendations |
| `review_expired` | Computed by readers when any evidence on a reviewed entry is expired or dated in the future |

`reviewed` is not a blanket statement of safety, complete conformance or independent
interoperability. The test report must state what was tested, exclusions, software
revision and reproduction steps. Independent interoperability and operational
reviews are separate evidence kinds. Affiliation and conflicts belong in the linked
report. Maintainers publish reasons for suspensions, corrections and reinstatements
through the review history; no participant, including a maintainer's own provider,
receives an exception to the evidence requirements.

Evidence expires on the stated date and should be renewed after material changes.
Consumers must show its dates and source. They must not turn a listing into an
automatic trust decision, silently update configured endpoints, or substitute a
directory entry for the Core's domain-to-issuer binding checks.

## Format and validation

Readers shipped before the AgentID integration variant must be upgraded to read
the expanded provider feed. The current parser still accepts legacy Core entries;
older strict parsers reject the new fields and variant rather than silently
treating AgentID as a Core provider.

The authoritative parser is `CatalogSchema` in `@agentlogin/mcp`; the generated
[JSON Schema](catalog.schema.json) supports editors and is refreshed by `npm run catalogs:build`.
Parser checks additionally enforce protocol URL syntax, reject duplicate identifiers/subjects,
wrong catalog kinds, missing review evidence, bad evidence chronology and mismatched
specification revisions. The editor schema alone does not perform all these checks.

Common entry fields are `id`, `name`, `operator`, `homepage`, `status`, `evidence`
and `updatedAt`. A provider adds `kind: "provider"`, `issuer` and `handleDomains`.
The protocol determines the remaining fields:

- `protocol: "agent-login"` uses `specRevision`, the 40-character Core specification
  commit. Legacy records without `protocol` retain this meaning, with no parser
  changes to their existing fields. `catalogView` resolves the omitted protocol to
  `agent-login` for display.
- `protocol: "agentid"` is provider-only and requires `protocolReference`, an HTTPS
  documentation URL. It must not contain `specRevision`. A documentation URL can
  change, so an evidence report must preserve the observed behavior, observation
  date and tested software version; the URL is not an immutable revision pin.

Core application records add `kind: "application"`, `clientType`, `clientId` and
`initiateLoginUri`. `clientType` distinguishes two forms:

- `open`: `clientId` is the exact HTTPS Client ID Metadata Document URL, with a domain
  host, a path and no dot path segments. Existing entries without `clientType` retain
  this meaning. Duplicate application identities are compared by this exact URL.
- `registered`: `clientId` is the exact opaque identifier assigned by the issuer;
  the required `issuer` is that exact HTTPS Issuer Identifier, without query or fragment.
  Duplicate application identities are compared by `(issuer, clientId)`, so the same
  opaque identifier at different issuers names different registrations.

Identifiers are never normalized. HTTPS URLs cannot contain userinfo or fragments.
The registering issuer is information about a registration, not an issuer acceptance
policy or permission to disclose Owner data. These catalog fields are a local product
format; the Core does not require catalogs or define their schema.

Core evidence is `{kind, url, observedAt, expiresAt, reviewer, revision}`, optionally
with `protocol: "agent-login"`. AgentID evidence instead requires
`{kind, url, observedAt, expiresAt, reviewer, protocol: "agentid", reference}` and
must not contain a Core `revision`. Its `reference` must exactly match the entry's
`protocolReference`. Evidence for one protocol cannot establish review of another.
`kind` is `domain_control`, `protocol_test`, `independent_interop` or
`operational_review`; dates are RFC 3339 timestamps and Core `revision` is the exact
specification commit. Reviewed entries of either protocol require the first two
kinds. AgentID review is scoped to AgentID; it never establishes Core conformance.

```sh
node packages/mcp/bin/agentlogin-mcp.js --check-catalog catalogs/providers.json
node packages/mcp/bin/agentlogin-mcp.js --check-catalog catalogs/applications.json
```

The MCP `agentlogin_catalog` tool can read operator-selected copies. It never fetches
or executes a listing's URLs. Installing this package grants no catalog entry access
to the user's keys or sessions.

## Public directory

After building the packages, run `npm run catalogs:build`. This validates both catalogs and writes a static site, JSON feeds and schema to `catalogs/dist`. Serve that directory on any HTTPS static host. The site states when review statuses were calculated and shows evidence expiry dates; rebuild after record changes. Machine consumers evaluate expiry themselves. No deployment or public listing is implied by generating the files.
