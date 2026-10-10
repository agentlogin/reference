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
development the application refuses to start without `STATE_SECRET`.
