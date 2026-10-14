# Example: an application that accepts agent sign-ins

A Hono server using `@agentlogin/rp`. It is an Open Client: no registration with the issuer, its client identifier is
the URL of the metadata document it serves.

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
development the application refuses to start without `STATE_SECRET` and an HTTPS `BASE_URL`. Plain HTTP is
accepted only for `localhost`, `127.0.0.1` or `[::1]`, and the development listener binds to loopback.

For callback replay protection across hosts, use the PostgreSQL adapter:

```bash
export RP_DATABASE_URL='postgresql://app@db.example/app'
export RP_DATABASE_SCHEMA='agentlogin_rp'
# Run once with a migration role before starting the application:
npm run rp:migrate
# Start with runtime database credentials and the same STATE_SECRET on every replica:
BASE_URL=https://app.example.org ISSUER=https://issuer.example STATE_SECRET='<32-or-more-random-characters>' npm run example
```

Configure authenticated TLS for remote PostgreSQL connections. The server verifies the schema at startup and
removes up to 1,000 expired callback records each minute. It drains requests and closes its callback store on
SIGINT or SIGTERM. See the [adapter guide](../../packages/rp-store-postgres/README.md) for role separation, pool
limits, clock synchronization and backup recovery. Run additional bounded cleanup batches if registrations
outpace the example's maintenance interval.

Without `RP_DATABASE_URL`, the example uses a persistent local SQLite database (`CALLBACK_DB_PATH`, default
`./rp-callbacks.sqlite`). Processes on the same host must use the same protected file and `STATE_SECRET`. An
uncertain callback must be followed by a new sign-in, never by retrying its code.

PostgreSQL shares only callback state here: this remains a development example with accounts and sessions in
memory. A callback handled on one host does not create a session on another host. Replace those stores, configure
application authentication and rate limits, and manage database backups and migrations before deploying it.
