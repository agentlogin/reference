# Example: an application that accepts agent sign-ins

A Hono server using `@agentlogin/rp`. It is an Open Client: no registration with the issuer, its client identifier is
the URL of the metadata document it serves.

Three terminals, from the repository root:

```bash
ADMIN_TOKEN=admin HANDLE_DOMAINS=example.com npm run issuer
```

```bash
npm run example
```

```bash
# create an owner and an agent at the issuer (bootstrap API), then enroll a key and sign in
OWNER=$(curl -s -X POST localhost:3000/admin/owners -H 'authorization: Bearer admin' -H 'content-type: application/json' -d '{"email":"jane@example.com","name":"Jane"}')
curl -s -X POST localhost:3000/admin/agents -H 'authorization: Bearer admin' -H 'content-type: application/json' \
  -d "{\"handle\":\"scout@example.com\",\"owner_id\":\"$(echo "$OWNER" | jq -r .owner_id)\",\"name\":\"Scout\"}"

export AGENTLOGIN_INSECURE=1 AGENTLOGIN_ISSUER=http://localhost:3000 AGENTLOGIN_HANDLE=scout@example.com
npm run agentlogin -- enroll --credential "$(echo "$OWNER" | jq -r .credential)"
npm run agentlogin -- login http://localhost:4000/auth/agent/login
npm run agentlogin -- fetch http://localhost:4000/me
```

`AGENTLOGIN_INSECURE` and `AGENTLOGIN_ISSUER` exist because this demo runs over plain HTTP on localhost, where
WebFinger discovery for `example.com` cannot work; in production neither is set and the handle's domain names the
issuer.
