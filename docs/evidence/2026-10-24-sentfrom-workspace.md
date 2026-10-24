# SentFrom and Agent Workspace candidate evidence

Prepared on 24 October 2026 for catalog review. Both entries remain `candidate`.
This is a scoped, Codex-assisted self-report prepared for SentFrom.ai, which operates
both services and develops this reference implementation. AI peer reviewers are
not independent implementers or external organisations. No certification,
completed independent interoperability, or general production-readiness claim
is made.

The protocol target is specification commit
`a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78`, the normative baseline subsequently
published as [working draft 0.2](https://github.com/agentlogin/spec/releases/tag/draft-0.2)
with status/date/documentation changes only.
Observation expiry for this candidate submission is **23 November 2026 00:00 UTC**.
Renew evidence after material changes. Expiry is a catalog operating choice, not
an Agent Login Core rule.

## Domain and metadata observations

The issuer is `https://identity.sentfrom.ai`, serving `mail.sentfrom.ai` handles.
Agent Workspace is an Open Client with identifier
`https://workspace.sentfrom.ai/client-metadata.json` and initiation URI
`https://workspace.sentfrom.ai/auth/agent/login`.

On 23 October, seven public domain-routing checks passed: WebFinger GET/HEAD
delegation to the intended issuer, missing/duplicate resource rejection, foreign
domain rejection, method rejection, and unrelated-path rejection. Existing MX
and SPF records were unchanged. The operator also inspected the deployed domain
route. This is affiliated deployment evidence, not an independent challenge of
the operator's legal identity or an assertion about other domains.

The first SDK discovery attempt received `404` because the test handle had not
yet been enrolled. That unsuccessful outcome is retained in the source evidence;
it was not counted as successful discovery. On **24 October 2026 00:56:53 UTC**,
after actual human approval and key proof, the live run observed domain WebFinger
`302`, an issuer response `200`, and the expected issuer identity.

Fresh unauthenticated HTTPS checks on **24 October 2026 16:48:20 UTC** independently
read the public metadata, without credentials, cookies, private handle queries,
redirect following, or insecure transport overrides:

| Document | Result | SHA-256 of response body |
| --- | --- | --- |
| `https://identity.sentfrom.ai/.well-known/openid-configuration` | `200`; exact issuer; `mail.sentfrom.ai` advertised; ES256 supported | `3edc727981c3ffe2725192bd54691d948b03711371919b18259ba8b15e08b79f` |
| `https://workspace.sentfrom.ai/client-metadata.json` | `200`; exact client ID and initiation URI; only the configured callback; authentication method `none` | `df1bab525499847bad08b47ff93202b40c848531b20e0faa20e86763bafaa797` |

These checks establish the observed endpoint responses and routing. They do not
exhaust the discovery or metadata requirements. A deployment health response alone
is not protocol evidence.

## Live protocol and application observations

The live acceptance run completed on **24 October 2026 00:56:53 UTC**, using the
real local helper and an already human-approved enrolled agent key. The reference
software revision was `c69238a45f72f2bfda1e39b7d7454a8de7bf58c6`.

All 12 recorded checks passed: unauthenticated reads were denied; sign-in
succeeded; account identity remained stable; a private note was saved/read;
identical writes were idempotent; conflicting writes returned `409`; helper
restart preserved its session; the old cookie could neither read nor write after
logout; local session state cleared; a fresh sign-in succeeded; the note remained;
and the final test session was signed out. The request used `openid`, `email`, and
`profile`; it did not request Owner email.

The initial conflict event recorded the successful readback's `200`, not the
conflict status. The recorder was corrected and the conflict check repeated with
explicit `409`; original events were retained. A separate AI reviewer checked
the driver, events, and evidence hashes for this bounded scope.

A clean installation completed on **24 October 2026 02:42:24 UTC** with 23 passed
checks. It installed actual local tarballs in a fresh consumer/cache without
workspace links, ran real MCP calls against live services, and restored the
existing approved identity. It tested modern and legacy MCP paths. The temporary
key/session copies were removed after logout. Its dependency audit reported zero
known production vulnerabilities at that time.

| Installed package | Version | Artifact SHA-256 |
| --- | --- | --- |
| `agentlogin` | `0.1.0` | `9741cc3d31caafe9fae2b488e9ec549cd3ae0bd5848ad7cf9228d5f4e1cf516e` |
| `@agentlogin/mcp` | `0.1.0` | `4a3d42b4c0f9af6c03befb236cde24009aa7b00bab7cca106a76f440737db235` |
| `sentfromai-mcp` | `0.4.1` | `8d094f0cc2f4aba486c13e1d71413d48698a81eefe954ed0e93c5f33015e2d9f` |

That run used reference revision `c69238a45f72f2bfda1e39b7d7454a8de7bf58c6`
and SentFrom revision `1aa0a6b4c185972c81d7ec8092b1b1a315284e75`.
These historical artifact versions are not evidence that the planned
`0.2.0-beta.1` / `0.5.0-beta.1` releases are published or accepted.

## Reproduction and exclusions

Use the exact recorded software/specification revisions to reproduce the historical
run, or record new versions as a separate result. An invited human must first
enroll an independently controlled factor and approve the agent's new key through
the documented Owner process. Use a claimed mailbox, protected helper state and
explicit Workspace configuration. Verify domain discovery; sign in; save/read a
non-sensitive note with a unique operation ID; restart the helper; test same-ID
and conflicting retries; log out; confirm the old cookie fails reads/writes;
sign in again and check the same account/note; finish signed out. Preserve secrets
privately and publish only redacted observations.

The supplied evidence does **not** establish:

- Fresh-customer onboarding using only published instructions. The clean install
  restored an existing identity; it did not create a new human or approve a new key.
- Registry or marketplace installation of the planned beta packages.
- A browser session: authentication belonged to the local helper.
- Fresh or changed-term consent in the clean-install run, which reused valid consent.
- Public traffic routed to particular replicas. Two instances were reported running,
  but this live traffic was not attributed to individual replicas.
- Email delivery, AgentMail/AgentID acceptance, Relay support, all Core obligations,
  independent interoperability, capacity, or live recovery/restore/rotation drills.

Local adversarial and operational tests are separate supporting evidence. They
must not be substituted for unperformed production or human checks.

## Source record integrity and privacy

The following SHA-256 digests identify the retained original records used to
prepare this summary. Originals are access-controlled because they include
test-account or infrastructure identifiers. The digests support later comparison;
they do not make those originals public or prove their contents independently.

| Source record | SHA-256 |
| --- | --- |
| 23 October discovery route results | `c355c3f068a9aa55a6639be16572d8802881eb4fb2b1b179fda4c265c57c4474` |
| 23 October discovery interpretation | `655f4a6007e79e1cbe898c7a1ab0433aa4b4eb8e97ade88e5b6724d73a788a3d` |
| 24 October live sign-in report | `9cc64b71f35a4f10ba36eb6c7ae19317c67d078e51e814970ae149c649abbceb` |
| 24 October clean-install report | `ff4bc1d11b5ace267002ee6bbd5e71cb9f5e6f2dd46ec937d3d28ee8d232b93c` |
| 24 October clean-install AI review | `f96f70bb7f7a4f5195db0b9169d20548aa231950000810e063473adf5f37d41d` |

This summary omits Owner addresses/IDs, credential fingerprints, private handles,
claim or approval links, inbox/note identifiers, tokens, cookies, private paths,
and cloud-account identifiers. No raw authentication or infrastructure screenshot
is published with it. The public entry remains a candidate for review; it grants
no application access or automatic trust.
