# Programme operator and decision authority

The Agent Login trusted-provider programme is operated by Brightboard AI Ltd,
trading as SentFromAI. This is the operator identified in SentFrom.ai's
[public terms](https://sentfrom.ai/terms). The programme is separate from the open
Agent Login specification and its governance.

This document defines the intended operating arrangement. It takes effect only
with an authenticated adoption record and a successfully verified first active
publication. Until then, the published feed remains a non-operational draft.

## Accountability and contact

SentFromAI is responsible for admission decisions, publication, renewal,
suspension, appeals and incident recovery. Its authorised maintainers use the
`agentlogin/reference` repository to publish decisions and release history.
[support@sentfrom.ai](mailto:support@sentfrom.ai) is the operational, security and
correction contact. Send sensitive incident details privately, without passwords,
tokens, private keys or live approval links. Public corrections can also use the
[repository issue tracker](https://github.com/agentlogin/reference/issues).

This initial programme has no promised response time or 24-hour staffing. Failure
to renew a policy or approval ends its acceptance automatically. Websites that
need a stronger availability commitment should use a policy and support
arrangement that provides it. They can block a provider locally at any time.

## Delegated review

The operator may use Codex-assisted review and the repository's tested automation
to assess evidence and prepare decisions. The authenticated decision authority is
`sentfromai-programme-maintainers`; its publication delegate is
`agentlogin-provider-policy-workflow-v1`.

That delegate may publish and renew releases derived from completed decisions in
the reviewed source, and remove acceptance when a decision expires or is
suspended or withdrawn. It cannot extend a provider's approval or evidence
expiry, invent passing evidence, restore a suspended provider without a new
decision, change the profile, or change the policy's trust root. An admission,
renewal or reinstatement requires a new evidence-based source decision.

No human reviewer quorum is required. The operator remains accountable for
automated decisions. The initial review of SentFromAI is affiliated self-review:
the programme operator also operates that provider, the reference implementation
and the Agent Tasks application. Separate agent reviews are not endorsements by
independent organisations. Each decision records its tools, sources, results and
limits.

## Authenticated publication

The publication origin remains
`https://agentlogin.github.io/reference/trusted-providers/v1.json`.
Repository write access, GitHub Actions, GitHub Pages and HTTPS form the version 1
trust root. There is no independent feed signature. Changing that trust root or
expanding the approved protocol profile requires a new website policy choice.

The `main` and `gh-pages` branches reject force pushes and deletion. The
`provider-policy-r*` release tags reject modification and deletion. Publishing
checks both source and publication history and commits the feed, page and state
together. The scheduled workflow uses its own short-lived GitHub token; npm
publishing credentials are not used for the provider list. Repository
administrators can change the protections, so these controls do not protect
against compromise of the repository's administrative authority.

See the [publication runbook](ACTIVE-PUBLICATION.md) for renewal, expiry alerts,
emergency suspension and recovery. A failed or stale publication never permits
fallback to the participant directory. An earlier backup must not erase a
suspension from the append-only decision history. Reinstatement is a new decision,
not an automatic consequence of the provider becoming reachable again.
