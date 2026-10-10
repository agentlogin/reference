# @agentlogin/issuer

Reference issuer for [Agent Login Core 1.0](https://github.com/agentlogin/spec) (draft 0.1): an OpenID Provider that
signs software agents in with keys they hold. Written against the specification section by section so that the code
reads as a second description of the protocol; Hono for HTTP, jose for JOSE, an in-memory store behind a small
`Store` interface.

```bash
npm run issuer            # http://localhost:3000, handle domain localhost, prints a generated ADMIN_TOKEN
ISSUER=https://issuer.example HANDLE_DOMAINS=example.com,*.agents.example ADMIN_TOKEN=... SIGNING_JWK='{...}' npm run issuer
```

Endpoints (spec section in brackets): `/.well-known/openid-configuration` and `/.well-known/jwks.json` (2.4, 7.7),
`/.well-known/webfinger` for served handles (2.2), `/authorize` GET and POST (5.1–5.3), `/transactions/{id}` with
`/assertion`, `/review`, `/continue/{secret}` and the `/wait` page (6), `/token` and `/userinfo` (5.6, 3.3),
`/register` (RFC 7591 with the admin token as initial access token, 4.3), `/agents/{handle}/...` management (7.2, 7.8),
`/owner/transactions/{id}` and `/decision` (6.6, API form).

Bootstrap, outside the specification: `POST /admin/owners {email, name}` returns an Owner Credential;
`POST /admin/agents {handle, owner_id, name}`; `POST /admin/credentials {owner_id, kind: "delegated", handle}`;
`PATCH /admin/agents/{handle} {enabled}`. All with `Authorization: Bearer ADMIN_TOKEN`.

Status: passes every check of `@agentlogin/conformance` (`npm test`). Not yet implemented: Ed25519 agent keys,
`private_key_jwt`, rate limits (6.7), Owner authentication pages (Owner Credentials are issued by the bootstrap API),
Relay profile (8), a database-backed `Store`, the `pairwise` subject type. Development mode (`INSECURE_DEV=1`, or an
`http` issuer) permits loopback clients and private addresses in metadata fetches; never run it that way in production.
