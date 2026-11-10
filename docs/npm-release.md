# npm beta release

As of 10 November 2026, all eight reference packages at `0.2.0-beta.4` are
published on npm and verified against their original release archives. Install
the exact version; existing `latest` defaults remain unchanged.

Beta.4 adds the public Agent Key fingerprint to MCP enrollment and status results,
including resumed requests and existing active keys. The private Workspace example
adds an optional provider-validity health check. Internal versions are coordinated;
external dependency resolutions are unchanged from beta.3. The RP's explicit
`issuerPolicy: agentLoginTrustedProviders()` option remains opt-in.

The [GitHub release](https://github.com/agentlogin/reference/releases/tag/v0.2.0-beta.4)
and [manifest](https://github.com/agentlogin/reference/releases/download/v0.2.0-beta.4/release.json)
retain source `275dcfe9b60fe55fe4ce5aa094c0871cd804616e` and all eight archive
hashes. The manifest SHA-256 is
`322ea84996070be5aa0d3ed43015ee60ee59663aaa7dd654ff11b04e08d4d5c2`.
The [original workflow](https://github.com/agentlogin/reference/actions/runs/42724726884)
passed 1,017 tests with PostgreSQL required and zero skips, plus a production
dependency audit with zero vulnerabilities. Publication completed on attempt 9
using the original prepared bytes and npm-generated GitHub provenance. Registry
metadata, tags and downloaded archives were checked against that manifest;
accepted versions were not rebuilt or replaced.

The matching `sentfromai-mcp@0.5.0-beta.3` companion, with an exact beta.4 MCP peer,
remains **unpublished**. Its [canonical workflow](https://github.com/sentfromai/sentfromai-mcp/actions/runs/42729085128)
passed preparation at `1b5a525f407c62910277a676ccecd199394ebbf7`, then publication
stopped with npm `ENEEDAUTH`. Its tested archive is preserved for the authorized
retry. The previously verified pairing of reference `0.2.0-beta.2` and
`sentfromai-mcp@0.5.0-beta.2` remains available.

A 10 November live acceptance used the published beta.4 reference packages with
that original, unpublished companion CI archive. It matched the existing active
public key fingerprint, signed in, read the existing synthetic Workspace note,
and logged out; the next helper request returned `not_authenticated`. It created
no new enrollment or note. Acceptance with all nine packages installed from the
public registry remains pending companion publication. This check did not test
new-Owner onboarding, old-cookie replay rejection or independent replica routing.

The [programme's published status](https://agentlogin.github.io/reference/trusted-providers/)
and unexpired policy determine current provider admission. Publishing packages
or documentation alone approves nobody. Websites can keep an explicit issuer
configuration or deliberately opt into the programme; errors never fall back to
unapproved issuers. AWS recovery access and rehearsal, UptimeRobot configuration
and an automatic alert drill, protected operator credential custody/provisioning,
and staffed coverage remain unfinished launch work.

These packages implement the working draft described in
[draft status](draft-0.2-status.md); package publication does not ratify the
specification. `@agentlogin/agentid-mcp` remains an experimental, separate AgentMail
AgentID integration, not Core interoperability or programme membership. Historical [beta.3 release evidence](https://github.com/agentlogin/reference/releases/tag/v0.2.0-beta.3)
and beta.2 evidence retain their original scope; beta.2 used maintainer
authentication and has no CI provenance.

Do not advertise a future release until its exact version and integrity have
been read back from npm and its clean registry consumer checks have passed.
A prepared bundle or local-only installation is not publication.

## Release contents

Publish the following coordinated version in this order. Internal package
dependencies are pinned to the exact release version, including the private example.

| Order | Package | Purpose |
| --- | --- | --- |
| 1 | `agentlogin` | Agent client and CLI |
| 2 | `@agentlogin/issuer` | Reference issuer |
| 3 | `@agentlogin/conformance` | Protocol test harness |
| 4 | `@agentlogin/agentid-mcp` | Separate experimental AgentID handoff adapter |
| 5 | `@agentlogin/rp` | Website sign-in integration |
| 6 | `@agentlogin/mcp` | Local Agent Login tools |
| 7 | `@agentlogin/store-postgres` | Shared issuer state |
| 8 | `@agentlogin/rp-store-postgres` | Shared RP callback state |

Application sessions and application data still need the application's own shared
store. The callback adapter does not supply either one. The private Hono example
is tested but is not published as an npm library.

Every public tarball includes its Apache-2.0 license. Only compiled JavaScript,
declarations, maps, reviewed executables/static resources, documentation and named
plugin examples/skills are allowed. Source tests, `.env`, `.npmrc`, private state
and arbitrary extra examples cannot enter the release bundle. The credential
pattern check is an additional check, not proof that arbitrary files contain no secrets.

## Local preparation

Use Node `22.23.4`, a clean committed checkout, and the committed lockfile. The
full PostgreSQL suite must pass against the intended commit. A local run without
`REQUIRE_POSTGRES_TESTS=1` is not a release check.

```sh
npm ci
REQUIRE_POSTGRES_TESTS=1 AGENTLOGIN_TEST_POSTGRES_URL=postgresql://localhost/agentlogin_test npm test
npm audit --omit=dev --audit-level=low
npm run release:prepare -- /absolute/path/outside-checkout/npm-beta
npm run release:verify -- /absolute/path/outside-checkout/npm-beta
```

Preparation removes generated `dist` and TypeScript incremental state, rebuilds,
and packs once with lifecycle scripts disabled. It rejects dirty source, stable
versions, mixed internal versions, local dependency paths and noncanonical package
metadata. Do not run another build or test against the same checkout concurrently.
The output directory must be new and outside the checkout.

Preparation installs the exact packed bytes in an isolated consumer with a new
npm cache, no workspace links, disabled lifecycle scripts, and the reviewed runtime
dependency resolutions. It imports all eight packages and runs each CLI's help.
The existing full-suite installed-consumer test separately exercises PostgreSQL
sign-in, useful application actions, two instances, logout and revocation.

The bundle contains eight `.tgz` files, `release.json` and `SHA256SUMS`. The manifest
records source commit, source lock digest, artifact SHA-256/SHA-512, packed file
inventory, runtime/tool versions and consumer results. Retain the bundle for the
release; do not repack it between test and publication. Verification rechecks the
bytes, inventory, license and package manifests against the same source commit.

## Registry access and first publication

Before publishing, confirm that the npm account controls the `agentlogin` name and
has publish access to the `@agentlogin` organization. A public registry `404` for a
scoped package does not prove that the account owns its scope. At preparation time,
`agentlogin@0.0.0` existed under `sentviaai`; the seven scoped package lookups
returned `404`.
The initial `0.2.0-beta.1` archives were published on 2026-11-02 with maintainer
authentication. Registry integrity and downloaded bytes were checked against the
original release manifest. This manual publication has no CI provenance.

Use [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) for ongoing
releases. Configure each package for organization `agentlogin`, repository
`reference`, workflow `npm-beta.yml`, and environment `npm-beta`. Permit direct
`npm publish` for this workflow. The workflow publishes only on an explicit dispatch
with `publish=true`; a push or tag never triggers publication.

New package creation may require the maintainer's authenticated first publication
before the package settings expose a trusted publisher. If this bootstrap is
needed, publish the **verified tarball** with the account's normal npm authentication
and required human 2FA, using `--access public --tag beta --ignore-scripts` and the
explicit npm registry. Do not create placeholder releases or place a long-lived
write token in this repository. A local bootstrap does not have CI provenance;
record that limitation instead of claiming it does. Configure and verify OIDC
for the next reviewed publication when it can complete within npm's
[two-day activation window](https://docs.npmjs.com/trusted-publishers/#trusted-publisher-configuration-expiry).
A workflow that only verifies and skips existing versions does not exercise OIDC
publication or add provenance to those versions. Do not repack an existing version
or publish a placeholder just to activate a trusted publisher.

### Initial registry tags

npm assigned both `beta` and `latest` to each of the seven newly published scoped
packages despite the explicit `--tag beta`. This behavior is also described in
[npm/cli issue 8490](https://github.com/npm/cli/issues/8490). The release verifier
therefore accepts this recorded initial default only for `0.2.0-beta.1` of
`@agentlogin/issuer`, `@agentlogin/conformance`, `@agentlogin/agentid-mcp`,
`@agentlogin/rp`, `@agentlogin/mcp`, `@agentlogin/store-postgres`, and
`@agentlogin/rp-store-postgres`. Matching immutable artifact bytes and the exact
`beta` tag remain mandatory. Other names and versions receive no exception, and
an existing `latest` default must remain unchanged throughout publication.
No release command sets or moves `latest` for a beta. Install the explicit beta
version rather than relying on a default tag.

During the first approval, registry metadata also exposed `0.0.0-stage` with the
description "Temporary package placeholder for staged publishing." The release
operator did not submit a placeholder publication command. Record this observed
registry behavior separately from the reviewed beta artifact; it is not a version
to install or reproduce. The attempted tag removal did not complete.

The package-wide metadata index initially returned `404` while the exact version
and direct dist-tag endpoints already exposed the publication. Such a `404` does
not prove a name or version is absent. Reconcile the exact version's integrity and
direct tags; inconsistent visibility stops publication for review rather than
triggering another upload.

The release workflow pins npm `12.2.1`, satisfying npm's current OIDC minimum, on
Node `22.23.4`. It uses GitHub-hosted runners, no dependency cache, commit-pinned
Actions and public-repository provenance. The build job has no OIDC permission;
the publish job performs no project dependency installation or package lifecycle
scripts. See [npm provenance](https://docs.npmjs.com/generating-provenance-statements/).

## Dispatch and recovery

1. Merge reviewed source to `main` and record the full commit SHA. Tag that same
   commit with its new release version; do not reuse or move an existing tag.
2. Dispatch **Prepare or publish npm beta** from `main`, supplying that version and
   SHA while it is still `main` HEAD. npm provenance identifies the workflow's
   dispatch commit, so an older checkout is not permitted. Leave `publish=false`
   for rehearsal; choose `true` for the authorized release.
3. The workflow runs the complete PostgreSQL suite, production dependency audit,
   artifact preparation and fresh consumer verification. It archives the bundle
   before starting the separate publish job.
4. Publication requires the canonical repository, `main` dispatch, matching
   immutable version tag and source commit equal to the workflow dispatch commit.
   It also checks that the commit is reachable from `main`. It uses the
   `beta` tag explicitly. Preserve existing default tags; the seven recorded
   initial scoped publications above are the only `latest` reconciliation exception.
5. Read back every published version's `dist.integrity`, then perform installation
   using only the public package names and pinned beta version in a fresh directory.
   Run the actual first-customer and second-site acceptance flows before announcing
   the beta. Reinstalling an existing identity does not prove new-owner onboarding.

Publication is not atomic across eight npm packages. If a run is interrupted, keep
the original bundle and rerun the failed publish job in the same workflow run,
which retains the original dispatch SHA and artifacts. The
script accepts already-published versions only when their integrity matches; a
different artifact under the same name/version stops the whole release. A failed
or uncertain publish is not retried blindly. Once all bytes are visible, finish
public-registry consumer validation before declaring the release usable.

After a successful upload, the publisher reads the exact version and direct
distribution tags with ten seconds between attempts, for at most five minutes.
It accepts only
the tested integrity, the intended `beta` tag and the unchanged `latest` tag
(including an absent `latest`). A 404 or the exact previous beta tag may still
be awaiting visibility. Conflicting bytes, unexpected tag changes, malformed
responses and network errors stop the run. This loop never uploads or repacks.
The 50-minute publishing job allows 40 minutes of readback across eight packages
plus setup and upload time; it remains an overall cap, not a completion guarantee.

npm distinguishes [validation from publication](https://api-docs.npmjs.com/#tag/Packages)
and [never permits reuse of a published name/version](https://docs.npmjs.com/cli/v12/commands/npm-publish/).
The five-minute limit is our waiting budget, not an npm propagation promise.
An expired wait means the accepted upload is unresolved, not absent. Preserve
the original artifact and establish its registry outcome before retrying the job.

Never reuse an npm version for a corrected artifact. Publish the next beta with
new evidence and keep the earlier version available for reproducibility. A code
rollback is a new package version; production service rollback is a separate operation.

## Evidence to retain

Keep the source commit/tag, CI run URL, bundle manifest/checksums, full test and audit
results, registry version/integrity readback, provenance status, and public consumer
test report. For onboarding evidence, say explicitly whether it used a new Owner,
new mailbox and newly generated agent key, and record any operator support required.
No local result alone proves capacity, independent interoperability, recovery or
permission to list a provider as reviewed.
