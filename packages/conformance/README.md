# @agentlogin/conformance

Black-box harness for Agent Login issuers. Each check corresponds to an item of the specification's
[conformance checklist](https://github.com/agentlogin/spec/blob/main/conformance.md) and reports pass, fail or skip
with the observed response.

```bash
npm run conformance -- --issuer http://localhost:3000 --admin-token TOKEN
npm run conformance -- --issuer https://issuer.example --handle scout@example.com --owner-credential CRED \
    --client-id ID --client-secret SECRET --redirect-uri https://rp.example/cb [--json]
```

Two modes. With `--admin-token` the harness creates its own owners, agents and registered clients through the
reference issuer's bootstrap API and runs every check; each run uses fresh handles and keys, so it can be repeated
against an issuer that keeps its state. With `--handle` and `--owner-credential` it uses an existing agent and needs
a client that already exists at the issuer: a Registered Client (`--client-id`, `--client-secret`, `--redirect-uri`)
or an Open Client (`--open-client-id`, `--open-redirect-uri`). Checks that need more than that are reported as
skipped, never as failed; without any client the run stops with a message before the first check. Some checks need something only the operator can supply
and report skip, naming what is missing, without it:

| Option | Supplies | Used by |
| --- | --- | --- |
| `--open-client-id URL --open-redirect-uri URI` | an Open Client metadata document you host (Section 4.2) | I-6, I-40 |
| `--invalid-open-client-id URL --invalid-open-redirect-uri URI` | a document the issuer must refuse, for example one stating `id_token_signed_response_alg` `RS256` (library: `invalidOpenClients`, any number) | I-39 |
| `--relay-issuer URL` | a Relay whose metadata the issuer can fetch, with `issuer` and `op_policy_uri` (Section 4.4); a domain name, so that look-alike hosts can be formed | I-45, I-48 |
| `--email-only-owner-credential CRED` | with `--handle`: a second Owner Credential of the same Owner, obtained through the issuer's one-time-code sign-in alone (library, with `adminToken`: `ownerEmailSignIn(email)`, which performs that sign-in) | I-45 |

Covered today: I-1 to I-4, I-6, I-7, I-9 to I-15, I-17, I-19 to I-24, I-26 to I-28, I-33, I-37 to I-49, and two checks
of the reference issuer's own surface: M-1 (Delegated Credential binding) and M-2 (the bootstrap `session_auth` marker).
I-49 runs last: it audits every response the whole run received from the authorization, transaction, token, UserInfo,
registration and agents endpoints. Owner approval (I-13, I-45) is exercised through the reference issuer's
`/owner/transactions/{id}` API, which the specification does not define.

Not observable black-box, so not covered: within I-43 an `expired` transaction (T_TXN); within I-44 the deletion of a
Consent Record unused for T_CONSENT; within I-45 the wording of the approval page and how the session behind
`--owner-credential` was established (the harness takes the operator's word that it qualifies under Section 6.6, and
proves only that a credential from the one-time-code sign-in does not). Within I-40 a loopback URI without a port is
not tested either way: Section 5.2 does not say whether it counts as a differing port. The library export
`runConformance(options)` returns the report as data.
