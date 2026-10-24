# Example: an application that accepts agent sign-ins

A Hono server using `@agentlogin/rp`. It is an Open Client: no registration with the issuer, its client identifier is
the URL of the metadata document it serves.

For the invite-only SentFrom deployment, use the [pilot runbook](../../deploy/pilot/README.md). It includes a
Railway container configuration and public/authenticated acceptance commands. These are deployment artifacts,
not evidence that a particular remote deployment or real Owner account has passed acceptance.

Once, from the repository root:

```bash
npm install && npm run build
```

Then three terminals, from the repository root. The issuer:

```bash
ADMIN_TOKEN=admin HANDLE_DOMAINS=example.com npm run issuer
```

The application, at http://localhost:4000:

```bash
npm run example
```

An agent: create an owner and an agent at the issuer through its bootstrap API, enroll a key, sign in.

```bash
OWNER=$(curl -s -X POST localhost:3000/admin/owners -H 'authorization: Bearer admin' -H 'content-type: application/json' -d '{"email":"jane@example.com","name":"Jane"}')
curl -s -X POST localhost:3000/admin/agents -H 'authorization: Bearer admin' -H 'content-type: application/json' \
  -d "{\"handle\":\"scout@example.com\",\"owner_id\":\"$(echo "$OWNER" | jq -r .owner_id)\",\"name\":\"Scout\"}"

export AGENTLOGIN_INSECURE=1 AGENTLOGIN_ISSUER=http://localhost:3000 AGENTLOGIN_HANDLE=scout@example.com
AGENTLOGIN_CREDENTIAL=$(echo "$OWNER" | jq -r .credential) npm run agentlogin -- enroll
npm run agentlogin -- login http://localhost:4000/auth/agent/login
npm run agentlogin -- fetch http://localhost:4000/me
```

The page at http://localhost:4000 shows the same sign-in as a form: enter `scout@example.com` and the browser is sent
to the issuer's wait page, which completes once an agent holding that handle's key asserts on the transaction.

Why the development switches: this demo runs over plain HTTP on localhost, where WebFinger discovery for
`example.com` cannot work. `AGENTLOGIN_INSECURE` and `AGENTLOGIN_ISSUER` tell the client so, and the application maps
`example.com` to the issuer itself (its `HANDLE_DOMAINS` variable, default `example.com`; set it to the issuer's handle
domains if you change them). In production none of these is set and the handle's domain names the issuer. Outside
development the application requires PostgreSQL, both shared secrets and an HTTPS `BASE_URL`, as described below. Plain HTTP is
accepted only for `localhost`, `127.0.0.1` or `[::1]`, and the development listener binds to loopback.

For several application hosts, use PostgreSQL for both callback state and application sessions:

```bash
export RP_DATABASE_URL='postgresql://app@db.example/app'
export RP_DATABASE_SCHEMA='agentlogin_rp'
export APP_DATABASE_SCHEMA='agentlogin_app'
export BASE_URL='https://app.example.org'
export STATE_SECRET='<at-least-32-random-characters>'
export SESSION_SECRET='<a-different-secret-of-at-least-32-random-characters>'
# Run once with migration credentials before starting any replica:
npm run rp:migrate
npm run example:migrate
# Switch RP_DATABASE_URL to runtime credentials, then start each replica:
ISSUER=https://issuer.example npm run example
```

Put replicas behind a load balancer that terminates HTTPS for the configured public `BASE_URL`; requests do not
need sticky routing. Every replica uses the same database primary, public `BASE_URL`, schemas and two secrets. Callback state remains
separate from application data: `@agentlogin/rp-store-postgres` coordinates the one-use login callback; the example's
`PostgresSessionStore` stores accounts and sessions. Login can finish on host A, `/me` can run on host B, and logout
on either host invalidates that session on every host. Application sessions use a fixed one-hour lifetime; reads do
not renew it. A new successful sign-in rotates the random session identifier and invalidates the old cookie in the
same transaction. Accounts use `(iss, sub)`, preserving their first sign-in timestamp across sessions and restarts.

Outside loopback HTTP development, startup requires PostgreSQL, HTTPS, and distinct `STATE_SECRET` and
`SESSION_SECRET` values of at least 32 characters. Use independently generated secrets from a secret manager.
`STATE_SECRET` protects pending login cookies; `SESSION_SECRET` protects session lookup and encrypts retained
Access Tokens. The database contains HMACs of the 256-bit random session identifiers, never the usable cookie
values. HTTPS uses a `__Host-sid` cookie with `Secure`, `HttpOnly`, `Path=/` and `SameSite=Lax`, without `Domain`.

Configure authenticated TLS for remote database connections. Both stores share one pool per process, bounded to
10 connections with a five-second acquisition timeout. Size the total connection budget across all replicas.
The server verifies both schemas before listening; ordinary requests do not run DDL. It drains requests and closes
both stores and their pool on SIGINT or SIGTERM. Each minute it runs non-overlapping batches of up to 1,000 session
or Access Token records and 1,000 callback records. Increase maintenance frequency if expired records accumulate.
Expiry is enforced at reads and transitions regardless of cleanup; retained live-check credentials are encrypted
and never returned after their expiry. Keep the application hosts and database clocks synchronized.

`PORT` sets the internal listener independently of `BASE_URL` (default: the explicit base port, otherwise 4000).
`GET /healthz` reports process liveness; `GET /readyz` reports startup-verified storage connectivity with a generic
`503` on failure or shutdown. Readiness queries share one in-flight check and cache its result for two seconds;
database acquisition and query timeouts bound each check to about seven seconds. No probe runs DDL, changes
sessions, fetches the Issuer, or returns connection details. Shutdown closes lingering HTTP connections after
15 seconds. A platform health check does not replace continuous availability monitoring.

The built example supports `npm start --workspace=agentlogin-example-rp-hono` and
`npm run migrate --workspace=agentlogin-example-rp-hono`; the latter installs the separate callback and application
schemas in sequence. Migrations are idempotent, but are not one cross-schema transaction; rerun after a failed
migration before admitting traffic. Both commands run compiled JavaScript without `tsx`.

Use a migration role to create the schema, and a separate runtime role with `USAGE` on the application schema,
`SELECT`, `INSERT`, `UPDATE`, and `DELETE` on `app_accounts`, `app_sessions` and `app_notes`, `SELECT` on
`app_schema_migrations`, and `EXECUTE` on `app_now()`. Restrict schema creation and changes to the migration role.
The [callback adapter guide](../../packages/rp-store-postgres/README.md) describes its separate runtime grants.
The application schema is scoped by `BASE_URL`; changing the public origin creates a separate account/session
namespace. Schema migrations are explicit and are independent of the issuer's database migrations.

`/workspace`, `/me`, `/notes`, `/logout` and authentication responses are marked `no-store, private`. `/notes` demonstrates
[Core Section 9](https://github.com/agentlogin/spec/blob/main/agent-login-core.md#9-relying-party-requirements): it calls UserInfo before accepting
an action, then rereads the session to detect logout or expiry during that request. Revocation or an expired
Access Token requires a new sign-in. Temporary Issuer or database errors return `503`; they neither claim a
successful logout nor clear a still-valid session. The workspace at `/workspace` stores actual private notes. `POST /notes` accepts JSON `{ "id": "<16-128 URL-safe characters>", "text": "<up to 4096 UTF-8 bytes>" }`. The client generates the ID before its first attempt and reuses it only for identical content. Session validity, credential expiry, the per-account limit of 1,000 notes and the note insert share one transaction. Logout serializes against that write. A lost acknowledgement can be reconciled by retrying the same ID; changed content returns `409`. `GET /notes` returns a page of up to 100 notes, bounded to 48 KiB of note JSON, for the signed-in `(iss, sub)` account. When `next_cursor` is present, pass it as `?before=` to read the next page. Invalid cursors return `400`; pagination never changes the account boundary. The request envelope allows 32 KiB so JSON escaping can represent every valid 4 KiB note. Notes survive logout and application restarts.

Application migration version 2 adds notes without changing existing accounts or sessions. It upgrades version 1 explicitly; runtime startup never changes the schema. This is a working pilot application, not evidence that an outside organisation has integrated Agent Login.

POST requests to `/notes` and `/logout` check the browser's Origin and Fetch Metadata headers against the exact
application origin, rejecting sibling origins too. Agent requests without browser headers remain supported.
This policy targets modern browsers; applications supporting legacy browsers that omit these signals need an
explicit CSRF-token mechanism. Do not add permissive CORS to these routes. See the
[OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Without `RP_DATABASE_URL`, only loopback HTTP development is allowed. It uses persistent local SQLite for callback
state (`CALLBACK_DB_PATH`, default `./rp-callbacks.sqlite`) and memory for application accounts and sessions. The
memory sessions disappear at restart and are not shared. An uncertain callback or session creation must be followed
by a new sign-in, never by retrying its authorization code.

Backups and failover must preserve acknowledged callback claims and session revocations. After a restore or a
failover that might lose acknowledged writes, invalidate both kinds of credentials before serving traffic: rotate
`STATE_SECRET` and `SESSION_SECRET` across every replica, without accepting old secrets as fallback. This ends
pending sign-ins and every old application session; preserved account records retain their first sign-in times.
Protect database rows, backups and logs as sensitive data, and never log cookies or Access Tokens. Account records
are retained until the application's retention policy deletes them; this example does not implement account deletion.

Shared storage makes this example work across hosts; deploying it still needs application authorization policies,
rate limits, monitoring, backup/restore procedures and capacity measurements. The reference issuer's documented
Owner authentication and other protocol gaps remain separate deployment work.
