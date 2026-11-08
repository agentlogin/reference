# SentFrom.ai Agent Login data disclosure

Prepared 8 November 2026 for the direct issuer `https://identity.sentfrom.ai`
and handles ending in `@mail.sentfrom.ai`. This supplements SentFrom.ai's
[privacy policy](https://sentfrom.ai/privacy) and [terms](https://sentfrom.ai/terms)
with the behaviour of the reviewed identity service. It does not describe other
providers or change an application's own privacy policy.

## Data used and shared

The service stores the Owner's account identifier and verified contact address,
Agent identities and handles, public agent keys, passkey public keys and device
metadata, approval records, application accounts and consent records. It also
processes short-lived challenges, encrypted browser state, hashed bearer/session
identifiers and security audit records. SentFrom does not receive a passkey's
private key, device PIN or biometric data.

The issuer sees which applications an Agent signs in to and when. It stores account
sign-in history and consent records; the current browser portal does not display
a complete history or consent list. Owners can request access through support.
Applications receive only the claims for the scopes actually granted:

| Scope | Disclosure |
| --- | --- |
| `openid` | The Agent's stable identity and the authentication result. |
| `email` | The Agent's handle and whether it is verified. |
| `profile` | The Agent's display name, username and Owner identifier. |
| `owner_profile` | The Owner's name and recorded verification-method label. |
| `owner_email` | The Owner's verified email address and recorded verification-method label. |

Owner scopes require a registered application and independent Owner approval or
an Owner-granted `share_owner` permission. An application cannot obtain them merely
by knowing an Agent's address. The
approval page identifies the application, destination, Agent and requested Owner
claims. The Agent reviews the disclosure and application terms. Material changes
to those terms require a new review; old consent does not silently add scopes.

SentFrom uses Clerk to identify the signed-in account and a separately verified
passkey for Owner approval. The identity service and its PostgreSQL data run on
Railway. The service's domain routing uses Cloudflare. The broader account and
mail service has additional providers described in the general privacy policy.

## Retention, revocation and deletion

Credential validity and physical record deletion are different. Revocation stops
authority immediately; retained records cannot restore it. Application sessions
belong to each application, so removing a key here does not itself delete those
sessions or the application's copy of previously disclosed data.

The reviewed implementation uses these lifetimes and cleanup rules:

- Authorization codes are valid for 60 seconds; access and ID tokens for at most
  10 minutes. A terminal transaction remains readable for five minutes through
  its original authorized access path, unless that authority has been revoked.
- Consent ceases to authorize disclosure after 180 days without use. It can be
  revoked earlier. Removing consent does not delete an application's account.
- Owner setup and pending agent-enrollment progress are saved for seven days.
  Owner approval sessions remain short-lived and require fresh verification.
  Individual sign-in requests have their own displayed deadlines.
- Cleanup runs in bounded batches. Expired records can remain stored while
  dependent security checks need them or cleanup is delayed. These validity
  periods are not promises of deletion at that exact second.
- Active account and signup records support identity continuity, sign-in history
  and account limits. Deleting an Agent or application account does not free a
  previously used signup place while its Owner exists.

The issuer's [published quota policy](https://identity.sentfrom.ai/policy) sets
the address-linkage period after Owner deletion to **zero seconds**. A new Owner
with the same verified email therefore inherits no previous signup counts.
Identity, credentials, approval and consent are never inherited. Minimal immutable
identity and revocation records remain where needed to prevent reuse or revival.
This zero-second setting concerns quota linkage; it does not promise immediate
erasure from backups, security records, the separate mail account or applications.

For account deletion, access requests or other privacy questions, contact
[support@sentfrom.ai](mailto:support@sentfrom.ai). The general privacy policy
describes those requests and material-change notices. The programme's public
decision and evidence must be reassessed if the reviewed disclosure or retention
behaviour changes.

## Verification scope

This is an affiliated implementation disclosure, not independent certification.
It is based on identity source `074175e59ae269be3135c4d865d7bca13dd34e73`, issuer
source `62c54330cca22a1ff0a61c4278431ca23457926d`, and the live quota policy read
on 8 November 2026. The admission report records deployment and test evidence
separately. Neither this document nor a successful health check admits a provider.
