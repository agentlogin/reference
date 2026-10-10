# Accepting agents with a stock OpenID Connect library

For the application, Agent Login is OpenID Connect: Authorization Code Flow, PKCE `S256`, an ES256 ID Token. A
standard library therefore works unmodified. This is exercised in CI with `openid-client` 6
(`packages/rp/test/stock-oidc.test.ts`): discovery, the authorization URL, the code exchange, ID Token validation and
UserInfo all pass against the reference issuer.

```ts
import * as oidc from 'openid-client';

const config = await oidc.discovery(new URL('https://issuer.example'), CLIENT_ID, undefined, oidc.None());
const verifier = oidc.randomPKCECodeVerifier();
const state = oidc.randomState();
const nonce = oidc.randomNonce();
const url = oidc.buildAuthorizationUrl(config, {
  redirect_uri: REDIRECT_URI, scope: 'openid email profile', state, nonce,
  code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
});
// ... redirect; on the callback:
const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
const claims = tokens.claims();
```

`CLIENT_ID` is either the HTTPS URL of a Client ID Metadata Document you serve (an Open Client, no registration) or
the identifier a registration gave you.

A stock library does not know the two Relying Party additions of the specification. Add them yourself, or use
`@agentlogin/rp`, which does both:

1. **`actor_type`** (Section 5.7 step 6): reject the token unless `claims.actor_type === 'agent'`.
2. **Handle binding** (Section 2.5): when the token carries `email`, confirm that discovery for the handle's domain
   yields the token's `iss`. Without it, a token is only as trustworthy as the issuer you configured: that issuer
   could name a handle in a domain it does not serve.

And follow Section 9: key accounts on (`iss`, `sub`), never on the handle; use the access token only at UserInfo and
treat a `401` there as revocation; expect `ES256` if your library defaults to `RS256`.

Hosted identity products that accept a custom OpenID Connect provider should work the same way, with the same two
additions. None has been tested yet; guides will be added only for configurations that were run.
