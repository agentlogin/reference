# agentlogin

Client library and command line for the [Agent Login](https://github.com/agentlogin/spec) protocol: a software agent
signs in to a web application with a key it holds, and the application receives a standard OpenID Connect ID Token
naming the agent and, when registered, its accountable owner. Apache-2.0. Tracks specification draft 0.1.

```bash
npm install -g agentlogin

# once: enroll a key for your handle with your Owner Credential (or a Delegated Credential)
agentlogin enroll --handle scout@example.com --credential "$OWNER_CREDENTIAL" --name laptop

# each sign-in: hand the client the application's "Sign in with your agent" URL and name the site
agentlogin login "https://issuer.example/authorize?response_type=code&client_id=..." \
  --handle scout@example.com --site https://app.example.org
# -> Signed in to app.example.org as scout@example.com (site answered 200)

agentlogin fetch https://app.example.org/api/me --handle scout@example.com   # uses the stored session cookies
```

Library:

```ts
import { AgentLogin, FileKeystore, FileCookieJar } from 'agentlogin';

const al = new AgentLogin({ handle: 'scout@example.com', keystore: new FileKeystore(), cookies: new FileCookieJar() });
await al.enroll({ credential: process.env.OWNER_CREDENTIAL!, name: 'server-1' });   // once
const result = await al.signIn({ authorizationUrl, expectedHost: 'app.example.org' });
await al.follow(result);                       // completes the application's sign-in; cookies are stored
const me = await al.fetch('https://app.example.org/api/me');
```

What it does, by specification section: WebFinger discovery of the handle's Issuer over HTTPS with the fetch
protections of 2.2 (A-1); sends the Authentication Request itself on the JSON path (5.3) so it is the Session Holder
and never sets `deliver_to_session` (A-4); verifies `iss`, the transaction URLs and the client's `redirect_host`
against the site you named before asserting (A-3); signs the assertion with an ES256 key from the keystore (6.3);
answers reviews and waits for Owner approval using `retry_after` (A-5); follows the continue step with the
`transaction_token` and fetches the redirect with a per-host cookie jar, never forwarding `Authorization` (A-6, A-9).
The code-bearing redirect URL is returned from `signIn` for `follow` and is never printed by the CLI.

Keys live in `~/.agentlogin/keys.json` (mode 0600) and cookies in `~/.agentlogin/cookies.json`; set
`AGENTLOGIN_HOME` to move them. The DNS fallback of Section 2.3 needs DNSSEC validation that Node.js does not expose
and is not implemented; `--issuer` / `AGENTLOGIN_ISSUER` pins an Issuer for development or a known deployment
(`handle_domains` is still checked). An operating-system keystore backend is planned.
