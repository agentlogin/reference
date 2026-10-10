# @agentlogin/conformance

Black-box harness for Agent Login issuers. Each check corresponds to an item of the specification's
[conformance checklist](https://github.com/agentlogin/spec/blob/main/conformance.md) and reports pass, fail or skip
with the observed response.

```bash
npm run conformance -- --issuer http://localhost:3000 --admin-token TOKEN
npm run conformance -- --issuer https://issuer.example --handle scout@example.com --owner-credential CRED [--json]
```

With `--admin-token` the harness creates its own owners, agents and registered clients through the reference issuer's
bootstrap API and runs every check. With `--handle` and `--owner-credential` it uses an existing agent and skips
checks that need more than one agent or a registered client. `--open-client-id URL --open-redirect-uri URI` adds the
Open Client checks (Section 4.2) for a metadata document you host.

Covered today: I-1 to I-4, I-6, I-7, I-9 to I-15, I-17, I-19 to I-24, I-26 to I-28, I-33, I-37 and the Delegated
Credential rules of Section 7.8. The library export `runConformance(options)` returns the report as data.
