# Agent Login reference implementation

Reference code for the [Agent Login](https://github.com/agentlogin/spec) specification: an issuer (sign-in
server), a relying-party library with a "Sign in with your agent" button, an agent command-line client and
SDKs, and a conformance test harness. Apache-2.0.

Status: draft 0.1 is the published baseline; this branch also implements selected draft 0.2 changes. See the
[pinned compatibility status](docs/draft-0.2-status.md) for implemented paths, remaining requirements and evidence
gaps. The reference issuer passes the partial harness on JSON and wait-page flows; this is not full conformance.
The implementation milestones are:

1. Direct sign-in issuer and partial conformance harness, including shared PostgreSQL lifecycle transitions, signing-key rotation and address-linked signup accounting. Production Owner authentication is supplied by the managed-service integration or an operator's equivalent integration.
2. Relying-party kit and Agent Workspace pilot: persistent notes, shared PostgreSQL accounts/sessions and live authorization checks. Framework-specific guides remain pending tested integrations.
3. Agent CLI, TypeScript SDK and local MCP/plugin: private enrollment, disclosure review, application sessions and bounded named operations. Python SDK work is separate.
4. Optional provider/application catalogs with review evidence, validation and a static directory. Relay implementation and independent interoperability remain separate milestones.

| Package | Purpose |
| --- | --- |
| `packages/mcp` | Local MCP tools and skills for enrollment, sign-in, configured application operations and logout |
| `packages/agentid-mcp` | Separate AgentID by AgentMail integration for documented browser sign-in handoffs to configured applications |
| `catalogs` | Optional provider/application records, review policy, validation and static directory |
| `packages/agentlogin` | Agent CLI and client library (npm `agentlogin`): discovery, enrollment, sign-in, cookie jar |
| `packages/store-postgres` | PostgreSQL issuer adapter: indexed records, serializable mutations, shared contracts and database concurrency tests |
| `packages/rp-store-postgres` | PostgreSQL RP callback adapter: shared registration and atomic one-use claims across application hosts |
| `packages/issuer` | Reference issuer (Hono + jose, written to the spec section by section) |
| `packages/rp` | Relying-party kit (`@agentlogin/rp`): validation per Sections 5.7 and 2.5, handlers, sign-in form |
| `examples/rp-hono` | A runnable application with PostgreSQL accounts and sessions shared across hosts |
| `packages/conformance` | Conformance harness |

The production issuer storage target is `@agentlogin/store-postgres`: normalized records, asynchronous connections and
atomic transitions across issuer instances. For RP replicas on several hosts, `@agentlogin/rp-store-postgres` provides
shared one-use callback storage in the application's PostgreSQL database. These are separate adapters: the RP store
does not hold issuer records or application sessions. The Hono example stores its accounts and application sessions
in separate PostgreSQL tables, so authenticated requests and logout work across application hosts. Memory and
SQLite remain local reference/test options.
Client locking, sign-in deadlines, cookie ordering and conformance validation have regression
coverage. See package READMEs for migration and storage requirements and [the product review record](docs/product-review.md) for review findings and evidence. The separate SentFrom.ai identity service supplies Owner authentication/approval, email verification and shared request limits; enabling it requires a correctly configured independent identity provider and delivery service. No local test establishes production capacity or independent interoperability.

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

For the issuer, see the [PostgreSQL issuer guide](packages/store-postgres/README.md): set `DATABASE_URL`, run
`npm run issuer:migrate`, and supply a persistent `SIGNING_JWK` when starting the issuer. For the application, see the
[PostgreSQL RP callback guide](packages/rp-store-postgres/README.md): set `RP_DATABASE_URL`, run `npm run rp:migrate`,
and use the same database, schema and `STATE_SECRET` across replicas. The
[Hono example guide](examples/rp-hono/README.md) adds shared application accounts and sessions: run
`npm run example:migrate` and provide a separate shared `SESSION_SECRET`. All stores verify migrations at startup;
ordinary requests do not run DDL. Other applications can use their own session infrastructure independently of the
callback adapter.
`npm test` reports PostgreSQL integration tests as skipped when `AGENTLOGIN_TEST_POSTGRES_URL` is absent;
`REQUIRE_POSTGRES_TESTS=1 npm run test:postgres` requires a configured database. CI runs the entire `npm test`
suite with PostgreSQL required, including client/RP tests, conformance probes, package artifacts and the example.
The database tests create isolated schemas and temporary restricted roles; use a dedicated test database and a
test user with schema-creation and role-creation privileges.
The clean-consumer test installs into a new npm cache using the exact tested lockfile resolutions and locally
packed workspaces. It needs registry access to fetch the locked third-party tarballs; a warm development cache
is neither required nor sufficient evidence of a clean installation.

For AgentMail's existing AgentID service, use the separate
[AgentID sign-in adapter](packages/agentid-mcp/README.md). It creates browser
handoffs through documented AgentMail APIs. The provider directory labels this
OIDC integration separately from Agent Login Core; listing either protocol never
changes a website's accepted providers automatically.
