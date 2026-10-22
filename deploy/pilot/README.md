# Agent Workspace private pilot

This runbook deploys the existing notes application against one explicitly accepted Issuer. SentFrom's private
pilot uses `https://identity.sentfrom.ai`, existing SentFrom Owners and an invite-only enrollment policy enforced
by the identity service. The application directory does not grant access. This repository does not configure
Owner authentication, invitations, mail-domain ownership or account recovery for the identity service.

## Deploy the application

Use a separate Railway service and application database. Build context is the reference repository root.
Configure the service through Railway's current Settings/API or [Infrastructure as Code](https://docs.railway.com/infrastructure-as-code).
Railway has deprecated `railway.json`/`railway.toml`: new services cannot opt in, and legacy support ends on
December 1, 2026. `deploy/pilot/railway.json` is a legacy settings reference, not a configuration path for new
services. Clear any legacy configuration-file selection when migrating; do not manage one service with both systems.

The Dockerfile builds the relevant workspaces
using `package-lock.json`, removes development dependencies, and runs compiled JavaScript as the non-root `node`
user. The recipe pins the Node 22.23.4 security release. Verify the resolved base-image digest and record the
final image digest when accepting a release; update the tested Node security patch as new fixes ship.
Building this source recipe is separate from accepting the resulting image.

```sh
docker build -f deploy/pilot/Dockerfile -t agent-workspace:pilot .
```

Apply and read back these settings on the actual deployment, including their source, before admitting pilot users:

| Setting | Required value |
| --- | --- |
| Build context/root directory | Reference repository root |
| Builder / Dockerfile | Dockerfile / `deploy/pilot/Dockerfile` |
| Start command | Image default: `node examples/rp-hono/dist/server.js` |
| Health check | `/readyz`, 60-second startup allowance |
| Restart policy | On failure, at most 5 retries |
| Replicas | 2, using the same public origin, schemas and secrets |
| Draining time | At least 30 seconds between SIGTERM and SIGKILL |
| Public domain target port | The service's `PORT` value, normally `4000` for this image |

The application closes remaining HTTP connections after 15 seconds; the longer platform drain allows storage
cleanup to finish. Verify a shutdown/redeployment rather than assuming that the settings file was applied.
Record deployment ID, source revision, image digest, replica count, health check and drain settings without
exporting environment-variable values. With IaC, review `railway config plan` before applying and reject changes
to unrelated services; then inspect the resulting deployment's effective settings.

Set these values through the platform's secret/configuration UI:

| Variable | Value |
| --- | --- |
| `BASE_URL` | Exact public HTTPS origin selected for this application; no path or query |
| `ISSUER` | `https://identity.sentfrom.ai` |
| `RP_DATABASE_URL` | Application PostgreSQL primary, with authenticated TLS when crossing an untrusted network |
| `RP_DATABASE_SCHEMA` | `agentlogin_rp` |
| `APP_DATABASE_SCHEMA` | `agentlogin_app` |
| `STATE_SECRET` | Independently generated random secret, at least 32 characters |
| `SESSION_SECRET` | Different independently generated secret, at least 32 characters |
| `PORT` | Platform-supplied internal port; not the public HTTPS port |

Do not set development issuer overrides, `AGENTLOGIN_INSECURE`, or a local callback database. `HANDLE_DOMAINS`
is unnecessary when the handle domain's verified discovery names the configured Issuer. Keep the same public
origin, schemas and secrets on every replica. Use two replicas for the pilot; no sticky sessions are required.
Their combined default database budget is 20 connections, plus migrations and monitoring.

Run both migrations once as a separate one-off job with DDL credentials, using the same built image:

```sh
npm run migrate --workspace=agentlogin-example-rp-hono
```

Switch to the restricted runtime database role before starting the service. The image intentionally does not
run migrations on startup or put DDL credentials in the app. See the [application grants](../../examples/rp-hono/README.md)
and [callback grants](../../packages/rp-store-postgres/README.md). The platform's readiness path is `/readyz`.
Both schemas must exist before the server listens. Liveness is `/healthz`; readiness includes a bounded
database check. Railway's deployment health check only gates deployment, so configure a separate continuous
monitor for health, readiness and the public metadata document.

Do not route protected production users to the pilot. Enforce invitation membership at the Issuer for every
enrollment and approval, including existing accounts, and require the approved independent human factor.
At the edge, apply request/connection limits to public login, callback and note endpoints; tune those limits
against the expected pilot concurrency. Never log full request URLs on authentication callbacks, cookies,
authorization headers, signing material or request bodies. Generic status/latency/error-code metrics suffice.

## Accept the deployment

After the public HTTPS domain and Issuer discovery work, run from a built reference checkout:

```sh
PILOT_BASE_URL=https://workspace.example node deploy/pilot/acceptance.mjs
```

This checks live readiness, the exact metadata/callback binding, and denial of an unauthenticated session request.
It does not create an account, sign in, or modify application data. The tool rejects redirects and bounds requests
and response bodies; it prints booleans, not tokens, cookies, private claims or response bodies.

For real sign-in, create a dedicated invited test Owner and Agent through the actual Owner flow. Enroll that
Agent's key after a fresh independent human approval. Set `PILOT_HANDLE`, `PILOT_ISSUER` and `PILOT_KEY_FILE` to
that Agent and its existing private keystore file, then run:

```sh
node deploy/pilot/acceptance.mjs --authenticated --accept-disclosure
```

`PILOT_BASE_URL` must also remain set. The explicit disclosure flag permits only `openid`, `email` and `profile`
for this exact application's metadata URL; it never permits Owner-email disclosure. The script waits up to five
minutes for a necessary human approval. Its cookies stay in memory. It signs in, writes one retained test note,
retries the same operation ID, checks exactly one note, logs out, replays the retired cookie to verify server-side
invalidation, signs in again and checks
the same immutable account and retained note. Each run consumes one note from the account's 1,000-note limit.
An unavailable final best-effort logout is not reported as a successful logout; the local cookie jar is discarded.

To test actual revocation, add `--revocation` in an interactive terminal. After the script has authenticated,
revoke the dedicated test Agent's key through the Owner dashboard and confirm the prompt. The next lasting
action must receive `401`/`revoked`. This changes the test Agent's authority intentionally; do not use a personal
or production Agent for this drill. Do not paste any enrollment credential, key, cookie or token into the terminal
prompt, a ticket or a report.

An HTTP success alone does not prove that different hosts handled it. The tool reports `crossHostEvidence: false`
until separate routing evidence is collected. During acceptance, force the callback onto another replica, restart
the first replica before reading the note, log out on one replica and verify rejection on the other. Record only
the replica labels, request outcomes and release digest. The existing deterministic two-host and installed-package
PostgreSQL tests cover these transitions locally; they do not substitute for this live deployment drill.

## Recovery and completion

Keep a tested backup and restore procedure. A restore that can lose acknowledged revocations is a security event:
rotate both application secrets across all replicas before reopening traffic, and coordinate the Issuer's own
restore/invalidation procedure. Never restore or rotate one replica independently and accept both secret sets.
The app intentionally retains notes until its retention policy deletes the account; use synthetic content in this pilot.

Accept the pilot only with real independent Owner authentication/enrollment, a live authenticated action, cross-host
logout, revoked-action denial, clean shutdown/restart, a restore drill, monitoring, and an external developer's
integration attempt. A candidate catalog entry, green unit suite or successful container build is not that evidence.

Implementation references: [Hono Node adapter](https://hono.dev/docs/getting-started/nodejs),
[Railway configuration migration](https://docs.railway.com/infrastructure-as-code),
[legacy configuration reference](https://docs.railway.com/config-as-code/reference),
[Railway deployment teardown](https://docs.railway.com/deployments/deployment-teardown), and
[Railway health checks](https://docs.railway.com/deployments/healthchecks). Protocol requirements remain in
[Core Section 9](https://github.com/agentlogin/spec/blob/main/agent-login-core.md#9-relying-party-requirements).
