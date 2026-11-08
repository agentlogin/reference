# SentFrom issuer recovery evidence

**Assessment: 8 November 2026. Evidence expires 23 November 2026 at 00:00 UTC,
or earlier after a material change to the bound implementation or recovery procedure.**

This report supports the recovery-rehearsal part of the trusted-provider
programme's Operations criterion for `https://identity.sentfrom.ai`, with
`mail.sentfrom.ai` as the proposed handle domain. The existing rehearsal shows
that restored, formerly valid authority is unusable after quarantine, and that
missing deletion or signup history keeps affected admission closed. It is not
an overall provider-admission decision or a claim that production restoration
has been performed.

Prepared by Codex for the SentFrom/Agent Login operator. This is affiliated,
automated evidence. A separate review agent independently reran the rehearsal;
that is independent execution within the same automated project, not independent
organisational endorsement or human approval.

The applicable programme requires a recovery rehearsal that prevents restored
backups from reviving revoked authority. It does not specifically require a
production snapshot restore or proof that all services can reopen. See the
[published criteria](https://github.com/agentlogin/reference/blob/8ce918578d21adde81567ee62058f1b4b710e7cf/trusted-providers/README.md#admission-evidence)
and the [companion recovery procedure](recovery-procedure.md).

| Binding | Verified evidence |
| --- | --- |
| Issuer identity runtime | SentFrom source `074175e59ae269be3135c4d865d7bca13dd34e73`; deployed image `sha256:565902de80eca62f7708d43dd5a5165e0baafbd8797c73e09700482ac0f83aea`. |
| Issuer and PostgreSQL implementation | Reference source `62c54330cca22a1ff0a61c4278431ca23457926d`, matching the deployed vendored packages. |
| Runtime artifact integrity | All 48 recorded artifact-file hashes match. Emitting the tested TypeScript sources reproduces all 42 first-party JavaScript modules in these three packages byte-for-byte: 19 identity, 18 issuer and 5 PostgreSQL modules. No runtime was executed for this comparison. |
| Rehearsal integrity | All 283 recorded source hashes and the frozen rehearsal inputs match. The independent result is dated 6 November 2026, 22:14:36 UTC. |
| Deployment observation | The operator's 8 November 2026, 22:18:26 UTC readback identifies the same deployed image as the 3 November artifact receipt. This assessment made no new provider call. |
| Database contract | Configured issuer schema `agentlogin`, version 3; identity schema `sentfrom_identity`, version 4. The operator's 6 November metadata receipt confirms these versions. The rehearsal used the same generated issuer schema under its isolated name `issuer`, and identity schema version 4. |
| Protocol reference | The deployed artifact records Core revision `a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78`. The recovery rule is implemented through invalidation and closed admission, not through a storage-engine requirement. |

The rehearsal's newer mail source was
`9924dd288560db86fa4ad97c543fa1abbf58b689`. Its identity runtime source is
unchanged from the deployed revision. The only identity-package differences are
the role-provisioning script and its documentation: they add rights for the two
new mail-worker tables and update their migration prerequisites. The older
artifact's role-plan heading says identity version 3; its executable schema and
checks already require version 4. The companion procedure uses the actual
version 4 contract. Full file comparisons are in
[binding-verification.json](binding-verification.json).

The rehearsal created valid synthetic signup credentials, a software WebAuthn
credential and Owner session, an enrolled Agent Key with an accepted signed
proof, and real store transactions, codes, access tokens, consent and accounts.
It saved backup T0, then acknowledged later revocation, suspension, credential
removal, Owner/email-code consumption, consent removal, another signup and Owner deletion
at T1. Restoring T0 demonstrably brought the old authority back. This positive
control matters: rejection was not caused by credentials that had never worked.

After the positive control, the target was restored to T0 again and its complete
row/schema fingerprints rechecked before quarantine. The relevant outcomes were:

| Restored state | Verified result after quarantine, repeated with fresh connections |
| --- | --- |
| Owner session and passkey setup | The real Owner-session guard rejects the old session. Disabled invitation state prevents passkey setup; the old setup base cannot authenticate. |
| Owner and Delegated Credentials | Both restored credentials are absent; stored Owner codes, email codes and pending passkey challenges are removed. |
| Agent Key and enrollment request | The Agent is disabled, its key is revoked, and the pending enrollment is denied. |
| Authorization code and access token | Redemption of the previously usable unredeemed code returns `void`; the restored access token is marked revoked. |
| Consent and transaction authority | Restored consent is absent, transaction bearer secrets are removed, reservations are released, and the known completed transaction retains its terminal timestamp. |
| Missing post-backup history | The fixture shows the signup count falling from two to one and a deleted Owner reappearing without its newer tombstone. The target application role stays NOLOGIN and admission stays closed; the test does not invent missing history. |

The application role in this fixture was newly created as NOLOGIN; this is not
proof that existing production sessions were terminated. The operational
procedure requires that separate containment step. Post-quarantine code rejection
was exercised through store redemption and Owner-session/passkey functions;
other key/token/consent checks include state assertions. This is not a full
post-restore HTTP sign-in or UserInfo test. The binding comparison covers
first-party modules, not a byte-identical deployment container or third-party
dependency installation.

The independently executed v3 run passed 21 checkpoints across 56 tables, with
two additional network-guard tests. Some checkpoints concern shared mail data;
they are not counted as extra issuer requirements. PostgreSQL was 18.6. The
fixture used pgvector 0.8.1, while the later production metadata reports 0.8.2;
vector search is not part of the issuer-authority result. The test's deletion
scenario deliberately retained a tombstone for one day. The current public
issuer policy uses zero post-deletion address-linkage retention. This rehearsal
therefore does not claim to test that production policy value; it demonstrates
why missing deletion history must keep uncertain authority and admission closed.

The independent result has SHA-256
`067c758093271adf36332c578cb0d7d935f05f7e15b29e354bc62ecaae46e374`.
The deployed artifact manifest has SHA-256
`fd8ccf3149dbfbf74b4ac029f9fc10ccfd44194dcdf9f06929bc107f43848794`.
The assessed quarantine has SHA-256
`6663c72be2a6f161b399f12253556cbc9e9a99aa9918e858953afb528c406638`.

Reproduction distinguishes two operations. The original rehearsal bundle is
retained by the operator for review: `run.ts`, `mail-probe.ts`, `quarantine.sql`,
`worker-fixtures.sql`, the authenticator/byte fixtures, source manifest, frozen
inputs and independent result. With that bundle and the pinned sources in its
recorded workspace layout, the recorded Node 22.23.4 invocation is:

```sh
node --test network-guard.test.mjs
node --import ./network-guard.mjs --import tsx run.ts
```

Use the stated PostgreSQL 18.6 and extension versions in an isolated environment;
provide no production credentials. The harness creates only synthetic data and
mocked external adapters, then removes its temporary cluster. Its linked
workstation dependencies are not a portable container attestation. This public
summary supplies the method, result and integrity pins; it does not claim that
the complete retained fixture/toolchain bundle has been publicly published.

The 8 November binding-only verification uses TypeScript 5.9.3 and the included
[verification script](verify-binding.mjs), against the operator's retained release
and rehearsal workspace:

```sh
node verify-binding.mjs /path/to/agentlogin
```

It verifies source/artifact hashes and JavaScript emission and executes no issuer
or recovery flow. The verification JSON records the individual module hashes.

No customer records, production credentials or real backup were read by this
assessment. No recovery suite was rerun because the relevant evidence and runtime
implementation were unchanged. Fresh artifact/source hashing and emission
comparison were performed. The software authenticator proves test behaviour,
not independent human device control. Handle reassignment during recovery and
complete post-backup ledger reconciliation are outside this rehearsal. There is
no claim of a live production restore, scheduled-snapshot recovery, S3 recovery,
RPO/RTO, or safe reopening without sufficient history.

**Scoped conclusion:** the recovery-rehearsal criterion is supported for the bound
implementation and the companion procedure's mandatory closed state. No additional
production restore is required to make this limited conclusion. Overall admission,
other operational criteria and permission to reopen a restored issuer remain
separate decisions. An admission record relying on this report must reference the
procedure and must not extend validity beyond the dates and scope above.
