# Publishing the programme draft

**Status: draft publication only. No providers are approved.** Publishing the
programme's documents does not activate its acceptance policy.

## Current publication

The existing GitHub Pages site serves the `gh-pages` branch at
<https://agentlogin.github.io/reference/>. There is no custom publication domain.
The programme page is `/trusted-providers/`; the SDK's fixed feed is
`/trusted-providers/v1.json` on that same origin.

From a reviewed source revision, run:

```sh
npm ci
npm run build
node --test trusted-providers/build.test.mjs
npm run catalogs:build
```

The catalog builder validates all inputs before replacing its generated
`catalogs/dist` directory. The draft publisher validates the feed with the actual
SDK at its original issue time, requires `status: "draft"` and no providers, and
copies its bytes unchanged. It rejects every active feed, even an empty one.
The output contains the directory and an explicitly non-operational programme
page. The original issue and expiry timestamps are historical, not evidence of
current publication health. No build updates them or reuses a revision with new
dates.

Publish only the reviewed `catalogs/dist` artifact through the repository's
existing Pages branch. Record the source revision, publication commit and feed
SHA-256. After deployment, fetch the fixed HTTPS address without following
redirects, compare the exact bytes and hash with the artifact, and confirm that
the public page says there are no approved providers. Test the fetched bytes
through the SDK at the real current time: they must refuse sign-in. A successful
HTTP response alone does not establish admission, freshness or correct content.

This draft can remain published after its historical expiry. It cannot enable
sign-in. Do not add a renewal schedule that makes an unapproved programme appear
operational.

## Before initial activation

Activation requires a separately reviewed publisher and these public records:

1. The adopted programme version; a named maintainer roster with affiliations,
   roles and authenticated decision channels; and the responsible incident contact.
2. The first completed admission decision, its application and evidence, exact
   issuer and handle domains, specification commit and validity period. Verify the
   two required human approvals, their authenticated references and disclosed
   conflicts against the [programme rules](README.md#decisions-and-accountability).
   Automated results and candidate catalog entries are not approvals.
3. The publishing access and branch/deployment controls, accountable publisher,
   refresh schedule and expiry alerts. Explain that the fixed HTTPS origin,
   repository publishing access, CI and host are the version 1 trust root. This
   format provides no independent signature or durable client rollback protection.
4. An independently exercised publication, emergency suspension and recovery
   procedure. Include incomplete deployments, unavailable or stale publication,
   expiry, concurrent refreshes, cold starts and in-flight callbacks. Restoring an
   older artifact must not re-admit a suspended issuer. Record the observed limits
   rather than claiming worldwide suspension within the SDK's cache interval.

The activation review must change the draft-only publication guard deliberately;
editing `v1.json` alone cannot activate this build. Machine checks can validate
record structure and consistency. They cannot establish a person's identity,
independence or genuine approval.

For the first active release, choose a revision greater than every previously
published revision, use fresh issue and expiry times no more than 24 hours apart,
and include only issuers with valid completed decisions. Every entry must exactly
match its approved issuer, domains, review URL, specification commit and review
expiry. Never extend approval past its earliest required evidence expiry. Validate
the release with the production SDK and independently verify the published bytes.
Later renewals also need a new revision; never retimestamp the same revision.

Initial activation requires the first genuine admission. Later releases may have
no accepted providers, for example when all are suspended. Removing an issuer
does not erase its decision history or remotely invalidate application sessions.
The [programme's publication limitations](README.md#publication-and-consumption)
continue to apply.
