# @agentlogin/mcp

Local MCP tools for Agent Login. A configured agent enrolls its key, signs in to a
configured application, and uses that application's session through the same helper.
Private keys, enrollment polling credentials, assertions, authorization codes and
cookies stay in the local process and private state directory. This does not sign a
separate browser in.

This package targets the pinned draft in [the compatibility worklist](../../docs/draft-0.2-status.md).
It is an implementation, not a conformance certification. No provider is preferred.

## Install and configure

Requires Node.js 22.13 or later. During development, install the locally packed
`agentlogin` and `@agentlogin/mcp` tarballs together. Registry installation is available
only after these versions have actually been published; this repository does not
publish them as part of a build.

```sh
npm install /absolute/artifacts/agentlogin-0.1.0.tgz /absolute/artifacts/agentlogin-mcp-0.1.0.tgz
```

Copy [the example configuration](examples/config.json), replace the reserved example
domains and absolute paths, and set the file to mode `0600`. The state directory must
be owned by the launching user with mode `0700`. Run:

```sh
./node_modules/.bin/agentlogin-mcp --check-config /absolute/private/agentlogin.json
```

Add a local stdio server to the MCP host. Use absolute executable and config paths;
use the host's protected environment/secret facility for enrollment API credentials.

```json
{
  "mcpServers": {
    "agentlogin": {
      "command": "/absolute/project/node_modules/.bin/agentlogin-mcp",
      "args": ["--config", "/absolute/private/agentlogin.json"]
    }
  }
}
```

The helper accepts current MCP 2026-07-28 and the SDK's supported legacy protocols.
It uses the official server SDK. Both modern and legacy stdio clients are exercised
in the package tests. stdout is exclusively the MCP channel during serving.

## Operator configuration

`identities` names the handles the user may use. Discovery establishes the issuer;
an optional explicit `issuer` pins a known deployment. A moved handle must be
re-enrolled at its new issuer. `ownerPortal` identifies the trusted human portal.
An optional `ownerApprovalPath`, such as `/identity/transactions/{transaction_id}`,
derives a direct approval link from that portal's origin and the validated,
nonsecret transaction identifier. It never uses an issuer-supplied action URL.

`applications` is an explicit target allowlist. Every entry has one exact `origin`,
a `loginPath`, and a JSON `sessionCheck` endpoint with JSON Pointers for the
authenticated handle, issuer and immutable subject. A callback response alone is
not evidence of authentication. Fresh sign-in first discards the previous local
jar, then requires the session issuer to match actual discovery and the completed
sign-in. Its `(issuer, subject, handle)` binding is saved privately and must match
on every application operation. Discovery is rechecked within its protocol cache
lifetime; a changed issuer selects a new session namespace and requires sign-in.
An unbound cookie jar from an earlier helper version also requires fresh sign-in.

Each named application operation fixes the HTTP method and path, accepted input
field names, and selected JSON output fields. Write operations use `inputFields`
for JSON body fields. GET operations may instead declare `queryFields`; their
inputs must be strings and are encoded as query parameter values. They cannot
replace query parameters already fixed in the configured path. Input is bounded
to 32 KiB. No tool accepts an arbitrary URL,
headers, cookie or bearer token. Responses are bounded to 64 KiB and only configured
fields are returned; known cookie values and credential-shaped fields are redacted.
Configure business-data endpoints, not token/debug/export endpoints. This redaction
is defense in depth, not a way to safely publish arbitrary secret-bearing responses.
The application must enforce its own authorization and CSRF protections.

The example `list_notes` operation returns one bounded page with `next_cursor`.
For the next page, pass that opaque cursor as `input: { "before": "<next_cursor>" }`
to the same operation. Stop when `next_cursor` is null. Pagination keeps each
notes response within the helper's 64 KiB response limit.

HTTP is permitted only for explicitly configured loopback URLs when
`developmentLoopback` is true. Production configuration uses HTTPS. Catalogs do not
alter this configuration or cause a listed issuer/application to be trusted.

## Tool flow

1. `agentlogin_inventory` lists identities, applications and operations.
2. If the identity needs a key, `agentlogin_enroll` begins or resumes enrollment.
   `agentlogin_enrollment_status` reports the public Owner approval link and outcome.
3. `agentlogin_sign_in` returns an operation identifier promptly.
4. Poll `agentlogin_status` no faster than its suggested interval. An
   `awaiting_consent` result contains the scopes, disclosure, client identifier,
   redirect host, client name, terms/privacy URLs and reason for review. These
   metadata strings are bounded untrusted text; links are not opened automatically. After the
   user's authorization, `agentlogin_review` allows or denies it. An
   `awaiting_owner` result supplies the transaction identifier and, when configured,
   a direct human approval link. It requires the real Owner's independent approval; an MCP
   review cannot provide it.
5. After `authenticated`, call `agentlogin_request` for user-authorized operations.
   Each request checks the current application session. It never follows an
   application redirect or retries a write. For idempotent APIs such as the example
   notes app, preserve the same input `id` for an explicitly requested retry after
   an uncertain network result.
6. `agentlogin_logout` invokes the configured application logout endpoint and clears
   the local jar only after a 2xx response. It does not revoke the agent key or a
   separate browser session.

Sign-in is bounded to 180 seconds by default (configurable from 10 to 600). Up to
four sign-in/request operations run concurrently, with only one per identity and
application. Duplicate sign-in starts reuse the live operation; new attempts have
a five-second cooldown. Tool calls have a 60-call burst and refill at one per second.
The issuer's poll intervals and 429 responses are respected by the SDK. Completed
sign-in summaries expire after fifteen minutes and the history is capped at 128.

## Enrollment broker integration

Core enrollment continues to use the issuer's proof-of-possession protocol. An
optional hosted broker allows the human to approve the generated public key without
putting an Owner Credential in an agent tool call. Configure `enrollmentEndpoint`
and `enrollmentCredentialEnv` on an identity. The latter names an injected provider
API credential; it is sent only to the exact configured endpoint, without redirects.

The broker contract used by the SentFrom.ai integration is:

| Request | Result |
| --- | --- |
| `POST enrollmentEndpoint`, provider bearer credential; `{handle, public_jwk, name}` | `201` with `{request_id, approval_url, polling_token, expires_at}` |
| `GET enrollmentEndpoint/{request_id}`, polling bearer credential | `200` with `status` `pending`, `approved`, `denied` or `expired`; optional `retry_after` |
| Approved response | `enrollment` contains `kid`, `status`, `expires_at`; a pending proof also contains `challenge`, `proof_url` |

`approval_url` must be exactly the configured endpoint's origin and path followed
by `/{request_id}/approve`, without query or fragment. The identifier is not approval
authority. The human authenticates separately. The helper checks the approved `kid`,
checks `proof_url` against discovered issuer metadata, and signs the Core enrollment
proof locally. This broker is a product integration, not an addition to Core.

The pending request, polling credential and key survive process restarts in mode
`0600` files. A lost proof response is reported as `enrollment_uncertain`; an
explicit retry polls that same request and accepts only the same key's `active`
status. It does not silently create a replacement identity. Expired/denied requests
require the operator to resolve or reset the enrollment record before a new request.
Enrollment runs are bounded and at most two run concurrently.

## State and failure handling

Keys and per-identity/per-application cookie jars live under `stateDirectory`.
The session namespace includes the actual handle, discovered issuer and origin,
not just friendly configuration names. Clearing cookies for fresh sign-in does not
revoke the former server session; use logout for server-side invalidation. One
serving process owns a directory at a time.
Never remove its lock while that process can resume. After an unclean crash, stop
all helpers before removing the abandoned `mcp-server.lock`.

The local filesystem must provide the atomic file operations the SDK requires.
This directory is not a multi-host storage adapter. Each local agent has its own
keys/sessions; the hosted issuer and application use their separate shared databases.
When the host closes stdio, the helper exits and stops pending network work. Pending
sign-in identifiers do not survive restart, but keys, enrollment requests and
application cookies do. A failed or uncertain operation is never labelled successful.

Install [the skill](skills/agent-login/SKILL.md) if the host supports skills. The skill
explains consent and output boundaries; endpoint access is enforced by the helper.

## Catalogs and verification

`agentlogin_catalog` reads explicitly configured, locally reviewed catalog files.
Validate a file with `agentlogin-mcp --check-catalog /absolute/catalog.json`.
See [catalog policy and format](../../catalogs/README.md) for evidence requirements.
The provider list includes unreviewed candidates; candidate status supplies no
review evidence or automatic trust. AgentID entries describe a separate OIDC
integration and require the [AgentID adapter](../agentid-mcp/README.md); this Core
helper does not treat those listings as compatible issuer metadata.
Application listings distinguish open metadata clients from registered clients, whose
opaque identifiers are scoped to their exact registering issuer. Neither form changes
the helper's explicit application or identity configuration.

Run `node --import tsx --test packages/mcp/test/*.test.ts` after the workspace build.
The suite covers the real stdio protocol, input validation, disclosure decisions,
callback and session binding, request limits, response redaction, concurrency,
enrollment recovery, catalogs and private storage. Whole-release clean-consumer
testing is run separately by the repository release checks.

Upstream references checked for this implementation:
[MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
[official SDK stdio](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html),
[legacy clients](https://ts.sdk.modelcontextprotocol.io/v2/serving/legacy-clients.html),
[Claude plugin manifests](https://code.claude.com/docs/en/plugins-reference).
