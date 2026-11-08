# SentFrom issuer database recovery procedure

**Applies to `https://identity.sentfrom.ai`: PostgreSQL issuer schema
`agentlogin` version 3 and identity schema `sentfrom_identity` version 4.**
This procedure supplements the deployed
[Owner enrollment and recovery runbook](https://github.com/samuelar2/sentfromai/blob/074175e59ae269be3135c4d865d7bca13dd34e73/packages/identity/docs/beta-operations.md).
It covers database rollback and restored authority. The runbook's `owner:admin
recover` command handles an individual lost factor; it is not a complete database
restore or general reopening command.

The responsible incident operator records the incident, known-good deployment,
backup time and intended recovery target. Authority and new admission remain
closed until the checks below pass. If post-backup history is insufficient, the
required outcome is **data available for restricted inspection, authority
quarantined, admission closed**. Availability pressure does not override that
outcome. No production execution is asserted by publishing this procedure.

1. **Contain the restored target before loading it.** Use an isolated target with
   no public listener, no application entrypoint and no background workers.
   Application roles stay NOLOGIN. NOLOGIN does not terminate existing sessions:
   stop every process that can use this target, terminate its remaining application
   database sessions, and verify no connection or reconnect path survives through
   an alternate credential, inherited role, ownership or PUBLIC grant. Only the
   controlled recovery operator may access it. Never point identity replicas,
   mail processes or relying parties at an unverified restore. In a real cutover,
   stop or reroute every process that could use the restored database before it
   becomes authoritative. A rehearsal must not overwrite the current primary.

2. **Bind the plan to the actual deployment.** Verify the issuer identifier,
   deployed image, schema versions and matching migration history. The bound
   identity implementation is `074175e59ae269be3135c4d865d7bca13dd34e73`, with
   reference `62c54330cca22a1ff0a61c4278431ca23457926d`. Verify the configured
   `ISSUER_DATABASE_SCHEMA`; do not substitute the fixture name `issuer` for
   production's `agentlogin`. Preserve the full mail migration history, including
   the legacy 014 entry. The shared mail lifecycle tables and triggers must remain
   consistent with identity bindings. A schema or implementation mismatch stops
   the operation for review; do not edit the version records to bypass it.

3. **Preserve evidence outside the rollback boundary.** Retain the original
   backup unchanged and collect acknowledged post-backup revocations, suspensions,
   deletions, ownership changes, consent changes, replay/consumption outcomes and
   signup accounting. Record original event times, immutable subjects and
   enrollment IDs. Also reconcile current client trust and signing-key history.
   Store recovery evidence and operator access separately from the restored
   database. A mutually consistent old backup is not evidence of current authority.

4. **Restore trusted data structures and validate transport.** Restore against
   the reviewed migration definitions, without importing source administrator
   roles, passwords or unreviewed executable DDL. Restore the shared mail,
   `agentlogin` and `sentfrom_identity` state from a consistent backup. Handle
   bootstrap seed rows and target-only trigger suppression explicitly, then
   restore the trusted triggers, rescan foreign keys, verify generated values,
   counters and hashes, and check sequence safety. Do not disable lifecycle
   triggers on the live source. A successful copy alone does not pass the
   following authority checks.

5. **Quarantine uncertain authority on the restored target.** Review and record
   one target-bound transaction implementing these controls before execution.
   The exercised fixture SQL has a synthetic database-name guard and must not be
   run unchanged against production. Instantiate the same controls for the exact
   restored target and configured schema; never use a connection chosen only by
   a convenient default environment variable.

| Restored scope | Required closed state |
| --- | --- |
| `sentfrom_identity.owner_passkey_users`, `owner_passkeys` | Disable uncertain invitation/admission state, advance its generation and revoke copied factors. Preserve audit evidence and earlier revocation times. |
| `sessions`, `owner_passkey_bases`, `owner_passkey_challenges`, `browser_state`, `owner_email_codes` | Invalidate copied sessions, setup bases, challenges, pending browser state and email codes. Base deletion must preserve the tested cascade behaviour. |
| `sentfrom_identity.enrollments` and `bindings` | Deny pending or approved requests and invalidate active bindings using the reviewed lifecycle functions. No request survives merely because it was approved before the backup. |
| `agentlogin.credentials`, `owner_codes`, `keys`, `revoked_keys` | Remove copied Owner/Delegated Credentials and one-use codes; revoke keys and preserve enrollment/revocation tombstones. |
| `agentlogin.agents`, `transactions`, `codes`, `access_tokens`, `reservations` | Disable and version-fence Agents; invalidate transaction secrets, codes and tokens; release reservations. Preserve established terminal outcomes and original expiry/retention semantics. |
| `agentlogin.accounts`, `consents` | Disable uncertain account grants and invalidate copied consent. New terms or missing withdrawal history require fresh review. |
| `agentlogin.clients`, `signing_keys`, `signing_state` and external signing configuration | Keep unreconciled trust/publication unavailable. Do not republish retired or compromised material from old configuration. Signing-key rotation alone does not repair restored authority. |
| Shared mail authorization and pending work | Fence copied mailbox API/claim credentials and any work that could change ownership, send, bill, call webhooks or delete data. Preserve uncertain outcomes for reconciliation; do not reset them into retryable work. |

6. **Keep identity and accounting uncertainty closed.** Reconcile immutable Owner,
   Agent and enrollment identities; a recreated handle must inherit nothing from
   its prior occupant. Preserve known deletion decisions, count provenance and
   original retention deadlines. Apply each deletion's actual policy; do not
   replace older deadlines with a fresh interval. The current public issuer policy
   has zero post-deletion address-linkage retention, which does not establish that
   a missing deletion happened or permit reuse of its immutable identity. Do not
   reconstruct lifetime counts by counting surviving Accounts. Without sufficient
   history, keep the affected identities, grants and owner/client admission closed.
   Fresh enrollment alone cannot resolve those gaps.

7. **Verify before any application access.** With the target still isolated,
   confirm no copied credential/session, active Agent Key, pending approval,
   usable authorization code, unrevoked access token or retained transaction
   secret can authorize. Check the actual schema's lifecycle/version bindings,
   zero reservations for invalidated work, disabled grants and unchanged original
   deadlines. Exercise the reviewed known-valid-then-restored test cases through
   the real store and Owner-session functions. Repeat after fresh connections or
   process restart. Record the failures expected from old authority, not just
   counts of modified rows. The application role remains NOLOGIN throughout this
   verification. Keep unrelated relying-party callback state and application
   sessions outside the claim: those applications own their invalidation.

8. **Reopen only the proven scope.** A responsible operator must separately approve
   the reconciled identity, quota, consent, client and signing state and verify the
   new configuration cannot republish old authority. Obtain fresh independent
   Owner verification and new enrollment where required, following the actual
   Owner runbook. Its `suspend` command has no unsuspend operation, and `recover`
   cannot reactivate a suspended invitation. There is no automatic reopen step in
   this procedure: legitimate readmission after quarantine needs a separately
   reviewed plan. If evidence is missing, leave the affected scope closed. Notify
   relying parties of the incident and coordinate their application-session
   response; do not claim issuer recovery revokes every external session.

9. **Close the recovery operation.** Record exact source/target revisions, backup
   time, original security events, verified invalidations, remaining exclusions,
   operator decision and any scope still closed. Keep personal evidence and
   credentials out of public reports. Disable temporary access, terminate its
   remaining sessions, remove temporary credentials and copies, and verify cleanup.
   Report production restore and reopening only if they actually occurred.

This procedure follows the specification's
[backup-restoration guidance](https://github.com/agentlogin/spec/blob/a000e29c7af91d3fd8a5a4ad6241e2b10aabcc78/implementation-guide.md#backup-restoration).
The bound [evidence report](recovery-report.md) identifies which controls were
exercised and what remains unproved. Publication of a recovery procedure neither
starts a recovery operation nor expands provider admission to other issuers,
domains or protocols.
