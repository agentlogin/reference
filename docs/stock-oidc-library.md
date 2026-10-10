# Accepting agents with a stock OpenID Connect library

For the application, Agent Login is OpenID Connect: Authorization Code Flow, PKCE `S256`, an ES256 ID Token. A
standard library therefore works unmodified. The test suite exercises this with `openid-client` 6
(`packages/rp/test/stock-oidc.test.ts`): discovery, the authorization URL, the code exchange, ID Token validation and
UserInfo all pass against the reference issuer.

```ts
import * as oidc from 'openid-client';

// Open Client: CLIENT_ID is the HTTPS URL of a Client ID Metadata Document you serve; no secret.
const config = await oidc.discovery(new URL('https://issuer.example'), CLIENT_ID, undefined, oidc.None());
// Registered Client: CLIENT_ID is the identifier the issuer assigned.
// const config = await oidc.discovery(new URL('https://issuer.example'), CLIENT_ID, undefined, oidc.ClientSecretBasic(CLIENT_SECRET));

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

Only the Open Client form is covered by the test.

A stock library does not know the Relying Party additions of the specification. Add them yourself, or use
`@agentlogin/rp`, which does all three:

1. **`actor_type`** (Section 5.7 step 6): reject the token unless `claims.actor_type === 'agent'`.
2. **`home_iss`** (Section 2.5): reject a token that carries `home_iss` unless its issuer is one you configured as a
   Relay and `home_iss` is among that Relay's `home_issuers`.
3. **Handle binding** (Section 2.5): when the token carries `email`, confirm that discovery for that handle yields
   the token's `iss` (or `home_iss` for a Relay token). Without it, a token is only as trustworthy as the issuer you
   configured: that issuer could name a handle in a domain it does not serve. The lookup goes to a host chosen by
   whoever presented the handle, so it needs the fetch protections of Section 2.2 (no private addresses, size and
   time limits); `discoverIssuer` from the `agentlogin` package applies them.

And follow Section 9: key accounts on (`iss`, `sub`), never on the handle; use the access token only at UserInfo, for
at most its lifetime, and treat a `401` there as revocation; expect `ES256` if your library defaults to `RS256`.

Hosted identity products that accept a custom OpenID Connect provider should work the same way, with the same
additions. None has been tested yet; guides will be added only for configurations that were run.
