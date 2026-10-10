# Agent Login reference implementation

Reference code for the [Agent Login](https://github.com/agentlogin/spec) specification: an issuer (sign-in
server), a relying-party library with a "Sign in with your agent" button, an agent command-line client and
SDKs, and a conformance test harness. Apache-2.0.

Status: milestone 1 landed (10 October 2026): the reference issuer passes the conformance harness end to end on the
JSON path and the wait-page path. The specification is at draft 0.1; code lands milestone by milestone:

1. Issuer core and conformance harness. Done except Ed25519 keys, `private_key_jwt`, rate limits and Owner
   authentication pages; see `packages/issuer/README.md`.
2. Relying-party kit: Better Auth helper, Clerk/Supabase/Auth0 guides, example app.
3. Agent CLI, SDKs and MCP server.
4. Federation: WebFinger discovery, relay, Docker image and one-click templates.

| Package | Purpose |
| --- | --- |
| `packages/agentlogin` | Agent CLI and client library (npm `agentlogin`) |
| `packages/issuer` | Reference issuer (Hono + jose, written to the spec section by section) |
| `packages/rp` | Relying-party helpers and the sign-in button |
| `packages/conformance` | Conformance harness |

Development:

```bash
npm install
npm test            # starts the issuer on a loopback port and runs the conformance harness against it
npm run issuer      # local issuer at http://localhost:3000 (development mode)
npm run typecheck
```

The issuer is written from scratch rather than on node-oidc-provider: the Sign-in Transaction (status, next step,
assertion, session binding without cookies) does not fit a cookie-based interaction model, and a self-contained
implementation that follows the specification section by section is the more useful reference.

Package names: npm `agentlogin` (reserved), PyPI `agent-login` (the name `agentlogin` is held by an unrelated 2019 project), crates.io `agentlogin` (free, not reserved).
