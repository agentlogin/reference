# Active policy publication and recovery

This publisher is separate from the historical draft builder. Its presence does
not activate the programme or admit a provider. With no `adoption.json` and
`decisions.json`, its workflow reports that the programme is inactive and does
not publish. `catalogs:build` continues to publish only the historical draft.

## Authority and records

`adoption.json` records the programme version and profile, accountable operator,
authenticated adoption reference, decision authority and delegated systems. It
pins the current historical Pages commit and feed SHA-256 for the first activation.
The fixed repository, source branch, publication branch and HTTPS endpoint cannot
be changed by a feed. The configured lifetime is between 1 and 24 hours.

`decisions.json` is an ordered, append-only public decision history. Each decision
identifies its authority, method, reason, exact issuer, date, review reference and
preceding decision for that issuer. Admission, renewal and reinstatement also
record the exact handle domains, immutable specification and tested source
revisions, affiliations, expiry and evidence for all six admission areas. Required
evidence must pass and remain valid through the decision's expiry. These checks
establish record consistency; they do not establish that assertions in an evidence
report are true or substitute for the programme's substantive review.

The field definitions and rejected cases are executable in
[publisher.mjs](publisher.mjs) and [publisher.test.mjs](publisher.test.mjs).
[publication-fixtures.mjs](publication-fixtures.mjs) contains only synthetic
`.example` records for tests, never admissions. Do not copy them into production.

A decision cannot silently transfer an issuer identity. A changed issuer needs a
new admission. Suspend and withdraw decisions remove the issuer from subsequent
releases. Reinstatement requires an explicit decision with complete current
supporting evidence and a reference to the suspension or withdrawal. Merely
renewing the feed, returning HTTP 200 or restoring an old source tree cannot
reinstate it. An appeal does not change acceptance.

After activation, past decisions and the adoption record are immutable to this
publisher. Corrections are new decisions. A change to adoption, delegated
authority or the publication trust root requires a separately reviewed migration;
editing those fields is rejected rather than silently expanding authority.

## Deployment controls

Before activation, protect `main` and `gh-pages` against force pushes and deletion.
Protect `provider-policy-r*` tags against updates and deletion, without bypass
actors. The dedicated `provider-policy` publishing environment must permit only the
canonical repository's `main` branch. Preserve the existing `github-pages`
environment used by legacy Pages deployment. These repository controls are part of the trust root;
repository and hosting administrators can still compromise it. Restrict access,
monitor administrative changes, and preserve these controls during recovery.

The workflow is [provider-policy.yml](../.github/workflows/provider-policy.yml).
Preparation has read-only repository permissions. The publishing job has only
repository-content and Pages write permissions, and uses the ephemeral GitHub
workflow token. Dependency installation receives no publishing token and disables
install scripts. Actions are pinned to reviewed commit hashes. The publishing job
runs only after the staged artifact exists; the artifact manifest digest passes
through a job output and is checked before any mutation.

Preparation runs the SDK validation and publisher tests, builds the site and
creates one artifact containing the whole generated site. The publishing job
rechecks current `main`, the Pages parent, the latest immutable release anchor,
source ancestry, adoption digest, complete decision prefix, artifact digest and
all file hashes. It recomputes the feed, state and programme page from the committed
source and checks fresh validity after any queue wait. Missing files, added files,
symlinks, tampering or a changed source/parent abort publication.

A private Git index creates one complete site commit. A non-force atomic push
updates `gh-pages` and creates `provider-policy-rN` together. Every new release has
a higher revision. Competing publishers cannot overwrite the winning branch or
leave only one of the two refs committed. Workflow concurrency reduces contention;
Git's atomic push and immutable tags prevent a stale publisher from overwriting
a newer published decision. Each release represents its recorded, validated
source snapshot. Immediately after the atomic push, and when reconciling a retry,
the publisher reads remote `main` again. If that read fails or identifies a newer
source, the workflow fails before requesting a Pages build. The already committed
release and anchor remain intact; the newer source's push-triggered run or a fresh
dispatch must prepare a superseding higher revision. Never roll back or rewrite
the committed revision. A retry cannot treat an old artifact as current merely
because its release commit exists.

This readback is not an atomic lock on `main`: another source change may arrive
after the final read and before or during Pages deployment. Its decision remains
pending until a subsequent release applies it. Source commit time alone is not a
promise of suspension at the public endpoint, and deployment still has CDN and
network propagation delays. The correctness boundary is the atomic publication
branch and release tag, not a claimed atomic transaction across source and hosting.

The site remains on its existing legacy Pages configuration. A workflow-token
push does not itself start a Pages build, so the job explicitly requests a build
through the Pages API. It then repeatedly fetches the exact feed, state and
programme page with redirects disabled and bounded response sizes, and validates
the feed with the production SDK at the current time. A queued build or HTTP 200
is not reported as success. Failure to observe the exact artifact within the
bounded check fails the workflow. It does not restore an older active release.

## Renewal, suspension and expiry

The schedule requests renewal every four hours, at minute 17. An adoption using a
12-hour release lifetime leaves time for missed runs, but schedules are not an
availability guarantee. GitHub can delay or drop scheduled runs and disable
scheduled workflows in inactive public repositories. Operators must monitor the
body's expiry and failed or missing runs; workflow failure notifications alone do
not detect a schedule that never ran. This repository does not claim those
external alerts are configured merely because the workflow exists.

A separate read-only [expiry monitor](../.github/workflows/provider-policy-monitor.yml)
runs at minutes 8, 23, 38 and 53. It fetches only the fixed HTTPS feed, uses the
production SDK, and fails before expiry when a 12-hour release or any provider
review has two hours or less remaining. For releases shorter than eight hours,
the release threshold is one-quarter of the adopted lifetime; the review threshold
stays two hours. A valid empty active release is reported as accepting no providers.
An unconfigured programme must serve its exact validated historical draft and is
reported **inactive**, never healthy-active. Malformed, changed, unavailable or
expired data fails the check. This monitor does not renew records or override expiry.

A manual dispatch with `simulate_failure: true` exercises a clearly labelled error
annotation, failed job, summary and JSON artifact without a network check, service
outage or policy change. These are inspectable alert records, not proof of delivery
to `support@sentfrom.ai`. Confirm notification subscriptions and actual receipt
separately. The monitor is separate from the renewal job but shares GitHub Actions
and its scheduling fault domain. A GitHub outage or disabled schedule can stop both;
an external monitor is still needed to detect missing checks and feed expiry during
that failure. A successful dispatch does not establish independent alert coverage.

A feed renewal issues a new revision and a fresh bounded feed expiry. It never
extends a decision or evidence expiry. Expired decisions are omitted. After the
first completed admission has activated the programme, an empty active release is
valid when every issuer has expired, been suspended or withdrawn. The initial
activation cannot be an empty release.

To suspend a provider, append a `suspend` decision with the exact current decision
ID in `supersedes`, the acting authority, reason, time and public incident reference.
Commit it through the authenticated `main` channel. The push starts publication;
manual dispatch with `publish: true` is also available. No human reviewer count or
external quorum is required. Keep sensitive exploit details out of public records.
Recheck the published feed and revision, and notify affected applications through
the programme's incident process. Websites may block an issuer locally at any time.

The SDK checks absolute release and review expiry and requests revalidation after
its local 60-second cache. CDN, publication and network delays are additional;
there is no worldwide 60-second suspension guarantee. Existing application
sessions remain the website's responsibility. If renewal or hosting fails, the
last published release expires and new sign-ins fail closed. Never extend a
review while investigating an incident, serve an expired feed with changed dates,
or configure an accept-all fallback.

## Recovery and uncertain commits

The immutable release tags are independent high-water anchors. Public state records
the last source commit, revision, adopted-policy digest, hashes of all decisions,
feed digest and original dates. A later publisher requires the newest anchor to
remain an ancestor of `gh-pages`, the source history to retain the last source
commit, and every old decision digest to remain unchanged. Restoring old Pages or
source data while retaining the anchors is rejected. A descendant commit that
removes or rewrites an earlier suspension is also rejected by the decision hashes.

Preserve the complete Git history and protected release tags during backup and
restore. Never reset `gh-pages`, delete an anchor, force-push an old branch, restore
an old artifact directly through hosting, or remove tag protection to make a
failed publication pass. The tags are not an independent cryptographic signature:
restoring the entire repository and its anchors to an old state or compromising
the host requires an independently established high-water mark and incident
recovery. If that mark cannot be established, stop publication and let the last
release expire; do not infer that the restored history is current.

If a push connection fails, the publisher reads both remote refs. It treats the
commit as successful only when both identify the exact intended commit. A retry
of the same artifact can reconcile the already-created tag and exact site bytes.
A conflict, superseded release or uncertain differing state aborts and requires
fresh preparation. Do not increment a revision manually or reuse a tag. A build
failure after a successful commit can be retried from that same verified artifact
while its source is still current and its decisions and release remain valid. If
source changed or validity ended, prepare a higher revision from current source.

The tests exercise complete and partial artifacts, real Git push contention,
source and Pages rollback after suspension, missing anchors, evidence expiry,
record tampering and incomplete live deployment. They do not establish live
operator coverage, externally delivered alerts or GitHub availability. Record
those separate production checks before claiming the programme is operational.

## Official platform references

- [GitHub Pages publishing sources](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
  explains workflow-token pushes and branch-based deployment.
- [Pages build API](https://docs.github.com/en/rest/pages/pages#request-a-github-pages-build)
  documents the explicit build request and Pages permission.
- [Scheduled workflow limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
  describe delays, dropped jobs and default-branch execution.
- [Workflow notifications](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs)
  explain notification subscriptions and which account receives scheduled-run notices.
- [Git push atomic updates](https://git-scm.com/docs/git-push#Documentation/git-push.txt---atomic)
  describe the all-or-nothing ref update used for release commits and anchors.
