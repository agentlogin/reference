# Agent Login reference implementation

Reference code for the [Agent Login](https://github.com/agentlogin/spec) specification: an issuer (sign-in
server), a relying-party library with a "Sign in with your agent" button, an agent command-line client and
SDKs, and a conformance test harness. Apache-2.0.

Status: milestone 1 landed (10 October 2026): the reference issuer passes the conformance harness end to end on the
JSON path and the wait-page path. The specification is at draft 0.1; code lands milestone by milestone:

1. Issuer core and conformance harness. Done except Ed25519 keys, `private_key_jwt`, rate limits and Owner
   authentication pages; see `packages/issuer/README.md`.
2. Relying-party kit. `@agentlogin/rp` done (10 Oct 2026): framework-agnostic core, web-standard handlers, sign-in form, example application (`examples/rp-hono`), tests against the issuer and the agent client. Better Auth, Auth.js, Clerk, Supabase and Auth0 guides are open and will be written against tested configurations.
3. Agent CLI, SDKs and MCP server. CLI + TypeScript library done (10 Oct 2026, end-to-end test against the issuer and a stub relying party); Python SDK and MCP server open.
4. Federation: WebFinger discovery, relay, Docker image and one-click templates.

| Package | Purpose |
| --- | --- |
| `packages/agentlogin` | Agent CLI and client library (npm `agentlogin`): discovery, enrollment, sign-in, cookie jar |
| `packages/store-postgres` | PostgreSQL issuer adapter: indexed records, serializable mutations, shared contracts and database concurrency tests |
| `packages/issuer` | Reference issuer (Hono + jose, written to the spec section by section) |
| `packages/rp` | Relying-party kit (`@agentlogin/rp`): validation per Sections 5.7 and 2.5, handlers, sign-in form |
| `examples/rp-hono` | A runnable application that accepts agent sign-ins |
| `packages/conformance` | Conformance harness |

The production storage target is `@agentlogin/store-postgres`: normalized records, asynchronous connections and
atomic transitions across issuer instances. Memory and SQLite remain local reference/test adapters. The RP requires
shared one-use callback storage; its bundled SQLite callback store is a single-host option, and a multi-host RP
needs a separate shared-database adapter. Client locking, sign-in deadlines, cookie ordering and conformance validation have regression
coverage. See package READMEs for migration and storage requirements; rate limiting and complete production Owner
authentication remain deployment work.

Development (Node.js 22.13 or newer):

```bash
npm install
npm run build       # needed once before the example or the CLI
npm test            # builds, then runs the conformance harness against the issuer and the client and kit end to end
npm run issuer      # local issuer at http://localhost:3000 (development mode)
npm run example     # example application at http://localhost:4000 (see examples/rp-hono/README.md)
```

The issuer is written from scratch rather than on node-oidc-provider: the Sign-in Transaction (status, next step,
assertion, session binding without cookies) does not fit a cookie-based interaction model, and a self-contained
implementation that follows the specification section by section is the more useful reference.

Package names: npm `agentlogin` (reserved), PyPI `agent-login` (the name `agentlogin` is held by an unrelated 2019 project), crates.io `agentlogin` (free, not reserved).

PostgreSQL storage is a separate optional package, `@agentlogin/store-postgres`. See
[its contracts and operations guide](packages/store-postgres/README.md). Set `DATABASE_URL`, run
`npm run issuer:migrate`, and supply a persistent `SIGNING_JWK` when starting the issuer. RP callback storage is
separate. `npm test` reports PostgreSQL integration tests as skipped when `AGENTLOGIN_TEST_POSTGRES_URL` is absent;
`REQUIRE_POSTGRES_TESTS=1 npm run test:postgres` requires a configured database, as the dedicated CI job does.
