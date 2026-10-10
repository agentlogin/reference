# Agent Login reference implementation

Reference code for the [Agent Login](https://github.com/agentlogin/spec) specification: an issuer (sign-in
server), a relying-party library with a "Sign in with your agent" button, an agent command-line client and
SDKs, and a conformance test harness. Apache-2.0.

Status: scaffold. The specification is at draft 0.1; code lands milestone by milestone:

1. Issuer core and conformance harness (the same harness also runs against AgentID).
2. Relying-party kit: Better Auth helper, Clerk/Supabase/Auth0 guides, example app.
3. Agent CLI, SDKs and MCP server.
4. Federation: WebFinger discovery, relay, Docker image and one-click templates.

| Package | Purpose |
| --- | --- |
| `packages/agentlogin` | Agent CLI and client library (npm `agentlogin`) |
| `packages/issuer` | Reference issuer built on node-oidc-provider |
| `packages/rp` | Relying-party helpers and the sign-in button |
| `packages/conformance` | Conformance harness |
