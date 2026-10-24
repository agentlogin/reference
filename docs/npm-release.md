# npm beta release

The first supported package release is `0.2.0-beta.1`, under the `beta` dist-tag.
It implements the working Agent Login draft described in
[draft status](draft-0.2-status.md); the package version does not publish or ratify
the specification. `@agentlogin/agentid-mcp` is an experimental, separate AgentMail
AgentID integration. Its inclusion does not establish AgentID/Core interoperability.

Do not advertise installation from npm until the exact version and artifact
integrity have been read back from the registry. Preparing a bundle or passing a
local consumer test is not publication.

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
`agentlogin@0.0.0` existed under `sentviaai`; the seven scoped packages were absent.

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
promptly afterwards; npm says a new trusted publisher must first publish within two days.

The release workflow pins npm `12.2.1`, satisfying npm's current OIDC minimum, on
Node `22.23.4`. It uses GitHub-hosted runners, no dependency cache, commit-pinned
Actions and public-repository provenance. The build job has no OIDC permission;
the publish job performs no project dependency installation or package lifecycle
scripts. See [npm provenance](https://docs.npmjs.com/generating-provenance-statements/).

## Dispatch and recovery

1. Merge reviewed source to `main` and record the full commit SHA. Tag that same
   commit `v0.2.0-beta.1`; do not move an existing tag to different code.
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
   `beta` tag explicitly. Never promote a beta to `latest`.
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
