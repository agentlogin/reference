# Participant catalogs

These optional public lists separate identity **providers** from **applications**
that accept Agent Login. They are discovery aids, not a central root of trust,
certification program or protocol requirement. Domain discovery identifies an
issuer; each relying party decides which issuers it accepts. The open specification
has no default provider, registry or relay.

The initial [provider](providers.json) and [application](applications.json) catalogs
contain no entries. The reference example and the planned hosted service have not
been given fictitious public verification or independent interoperability evidence.
Anyone can host a copy or maintain a different acceptance policy.

## Submission and review

Submit a pull request containing the operator's identity/contact page, exact issuer
or client identifier (and its registering issuer for a Registered Client), supported handle domains or initiation URI, and the 40-character
specification commit being implemented. A reviewer checks control of the named
domain and attaches reproducible protocol test evidence for that exact revision.
Evidence records identify the reviewer, observation date, expiry date and public URL.
Do not include credentials, personal Owner addresses or raw security artifacts.

Status has a narrow meaning:

| Status | Meaning |
| --- | --- |
| `candidate` | Submitted information; no review conclusion |
| `reviewed` | Domain-control and protocol-test evidence supplied for the listed revision |
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

The authoritative parser is `CatalogSchema` in `@agentlogin/mcp`; the generated
[JSON Schema](catalog.schema.json) supports editors and is refreshed by `npm run catalogs:build`.
Parser checks additionally enforce protocol URL syntax, reject duplicate identifiers/subjects,
wrong catalog kinds, missing review evidence, bad evidence chronology and mismatched
specification revisions. The editor schema alone does not perform all these checks.

Common entry fields are `id`, `name`, `operator`, `homepage`, `status`,
`specRevision`, `evidence` and `updatedAt`. A provider adds `kind: "provider"`,
`issuer` and `handleDomains`. An application adds `kind: "application"`, `clientType`,
`clientId` and `initiateLoginUri`. `clientType` distinguishes two forms:

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

Each evidence entry is `{kind, url, observedAt, expiresAt, reviewer, revision}`.
`kind` is `domain_control`, `protocol_test`, `independent_interop` or
`operational_review`; dates are RFC 3339 timestamps and `revision` is the exact
specification commit. Reviewed entries require the first two kinds.

```sh
node packages/mcp/bin/agentlogin-mcp.js --check-catalog catalogs/providers.json
node packages/mcp/bin/agentlogin-mcp.js --check-catalog catalogs/applications.json
```

The MCP `agentlogin_catalog` tool can read operator-selected copies. It never fetches
or executes a listing's URLs. Installing this package grants no catalog entry access
to the user's keys or sessions.

## Public directory

After building the packages, run `npm run catalogs:build`. This validates both catalogs and writes a static site, JSON feeds and schema to `catalogs/dist`. Serve that directory on any HTTPS static host. The site states when review statuses were calculated and shows evidence expiry dates; rebuild after record changes. Machine consumers evaluate expiry themselves. No deployment or public listing is implied by generating the files.
