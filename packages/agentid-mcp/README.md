# AgentID sign-in MCP adapter

This local stdio plugin starts **AgentID by AgentMail** sign-ins for one exact
configured inbox and named, allowlisted apps. It is a separate integration from
`@agentlogin/mcp` and does not claim Agent Login Core
compatibility, enrollment, domain delegation or conformance.

It uses published AgentMail APIs and leaves browser enrollment, consent and the
application callback to AgentID's browser flow. It does not use undocumented
wait-page endpoints, generate agent keys, obtain application cookies, open a
browser or perform application actions. A `202` response means the handoff was
created. An `active` key means the credential was activated. Neither establishes
that the application accepted the login or has a current session. Verify that
separately in the browser which completed the handoff.

## Setup

Requires Node 22.13+. In this source checkout:

```sh
npm ci
npm run build
node packages/agentid-mcp/bin/agentid-signin-mcp.js --help
```

Create an operator-owned configuration file outside your repository, mode `0600`.
Start from [examples/config.json](examples/config.json), replace the inbox and
populate named applications with their permanent AgentMail `app_id` (UUID):

```json
{
  "version": 1,
  "inbox": "your-agent@agentmail.to",
  "credentialEnv": "AGENTMAIL_API_KEY",
  "applications": {
    "notes": {
      "appId": "11111111-1111-4111-8111-111111111111",
      "name": "Your notes app",
      "origin": "https://notes.example.com"
    }
  }
}
```

The example app UUID and domain are placeholders, not live registrations. Use
the real app ID from AgentMail's catalog or app operator. Slugs are intentionally
not accepted for configuration because the permanent ID is the authorization
target. The origin is a human review aid, not a substitute for checking the
provider's displayed app. There is no default app allowlist; browsing never
changes it. Empty application configuration allows catalog browsing only.

Inject the API key through the host's protected environment/secret facility as
`AGENTMAIL_API_KEY`. Use an inbox-scoped key where practical, with `app_connect`
for connect, `api_key_read` for credential status, and `inbox_read` for account
history. `app_share_owner` is needed only when authorizing a disclosure of owner
details. Never paste credentials into this config, tool arguments or chat. This
adapter cannot create AgentMail organizations or inboxes, recover keys or change
permissions. Completing the browser flow can create an account at the selected
app when the inbox has not signed in there before.

Validate and launch:

```sh
node packages/agentid-mcp/bin/agentid-signin-mcp.js --check-config /absolute/private/agentid.json
node packages/agentid-mcp/bin/agentid-signin-mcp.js --config /absolute/private/agentid.json
```

Alternatively set `AGENTID_MCP_CONFIG` to the absolute config path. The checker
validates only local structure; it makes no API call and does not verify your
credential, inbox or app registrations.

Add the command to a stdio MCP host using [examples/mcp.json](examples/mcp.json),
replacing both absolute paths. Use the host's secret injection mechanism rather
than adding an API key to that example. The packaged
[agentid-sign-in skill](skills/agentid-sign-in/SKILL.md) supplies the workflow for
hosts that support local skills; copy its folder into your host's skill location
or reference it from your plugin packaging. The skill and MCP server are included
in the npm package; this does not install them into a user's host automatically.

AgentMail also offers its own broader [hosted MCP server](https://github.com/agentmail-to/agentmail-skills/blob/main/agentmail-mcp/SKILL.md)
at `https://mcp.agentmail.to/mcp`. This adapter is a narrow alternative for
operator-configured sign-in targets, not AgentMail's official plugin.

## Tools and browser handoff

| Tool | Effect |
| --- | --- |
| `agentid_inventory` | Read the configured inbox and app aliases without network access. |
| `agentid_list_apps` | Browse one catalog page; a local `nextCursor` continues pagination. |
| `agentid_get_app` | Read public details for one configured app. |
| `agentid_connect` | Start sign-in to a configured app with explicit `acceptDisclosure`. |
| `agentid_key_status` | Read the credential for a connect operation created in this process. |
| `agentid_accounts` | Read configured-app account history for this inbox. |

Request sign-in only after the user selects the intended app. Generate a UUID
`attempt` for `agentid_connect`, and preserve it for identical retries. The
helper sends it as AgentMail's documented `Idempotency-Key`. It never retries a
write automatically and refuses to reuse a local attempt with different inputs.
After an uncertain response, reuse the same attempt instead of creating another.
The provider ultimately controls idempotency retention.

`acceptDisclosure` is required, with no true default. Use `false` to leave the
disclosure review in AgentID's browser flow. Use `true` only with explicit
authorization for that app's disclosure, including owner data if requested.

The handoff returns `browserHandoffUrl` only after validating the exact
`https://auth.agentid.com` origin, no credentials or fragment, and a future expiry
within the documented five-minute lifetime plus one minute of clock tolerance.
**This URL is a sensitive single-use credential.** It is the one intentional
secret-bearing output so the operator can complete the sign-in. Do not log,
publish, save or forward it; do not auto-open it. An MCP host may retain tool
results in conversation history, so use a trusted host and operator conversation.
The helper never requests that URL and does not follow it to the application.

Key-status operations and pagination cursors exist only in memory, expire after
15 minutes, and are bounded. Restarting loses those references; it does not
revoke provider keys or end a browser session. Stored key activation is distinct
from application session state. Account records report sign-in history only.
Poll no faster than every five seconds. Empty catalog/account pages can still
have a `nextCursor`; stop pagination only when it is absent.

The app allowlist limits this helper's requests, not the authority of the
browser's resulting sign-in key. AgentMail copies `app_connect` and
`app_share_owner` permissions from the creating bearer key. Deleting or changing
that bearer key does not revoke the sign-in keys it created. Revoke those keys
separately through AgentMail; existing app sessions have their own lifetimes.
See AgentMail's [credential lifecycle](https://docs.agentmail.to/agentid-sign-in#credential-lifetimes).

There is no `authorize_inbox` tool. Although AgentMail documents that endpoint,
it accepts a transaction token without an independent documented API for this
adapter to bind it to the configured app. A caller-supplied app name or claimed
browser origin would not prove that binding. Use the configured app's connect
handoff. A future adapter can add token authorization when upstream supplies a
stable transaction-inspection contract.

## Boundaries and failure handling

All API requests go to the hard-coded US API origin `https://api.agentmail.to`.
There is no base-URL override. Redirects are rejected, responses are capped at
64 KiB, the entire request/body read has a ten-second deadline, and each process
allows two concurrent requests and thirty starts per minute. Catalog entries
and provider instructions are never executed. Selected response fields are
returned; error bodies, raw key objects, bearer credentials, token fields and
upstream instructions are omitted. Known API-key values are redacted from text.

Provider rejection, unavailable service, invalid response, request uncertainty,
missing credentials and expired local operations produce fixed error codes.
Errors do not expose HTTP bodies or request headers. Do not interpret an error
as proof that a POST did not reach the provider. Secret-free configuration errors
go to stderr; stdout carries MCP only during server operation.

## Published contracts and verification

Implementation checked against the official docs and public discovery on
16 October 2026:

- [AgentID discovery](https://auth.agentid.com/.well-known/openid-configuration)
- [List Apps](https://docs.agentmail.to/api-reference/apps/list) and [Get App](https://docs.agentmail.to/api-reference/apps/get)
- [Connect App](https://docs.agentmail.to/api-reference/apps/connect) and [sign-in lifecycle](https://docs.agentmail.to/agentid-sign-in)
- [Get API Key](https://docs.agentmail.to/api-reference/api-keys/get) and [inbox account history](https://docs.agentmail.to/api-reference/inboxes/accounts/list)

Tests use mocked HTTP and a real MCP stdio client. They cover fixed-origin
requests, app/inbox boundaries, redirects, timeouts, oversized responses,
pagination, idempotency, disclosure handling, credential-status boundaries,
redaction and packaging. They create no AgentMail accounts and perform no live
authenticated sign-in. A live browser/application sign-in remains a separate
operator-authorized integration test.

```sh
npm run build
node --import tsx --test packages/agentid-mcp/test/*.test.ts
```
