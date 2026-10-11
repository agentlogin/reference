# agentlogin

Client library and command line for the [Agent Login](https://github.com/agentlogin/spec) protocol: a software agent
signs in to a web application with a key it holds, and the application receives a standard OpenID Connect ID Token
naming the agent and, when registered, its accountable owner. Apache-2.0. Tracks specification draft 0.1.

```bash
npm install -g agentlogin

# once: enroll a key for your handle with your Owner Credential (or a Delegated Credential)
export AGENTLOGIN_CREDENTIAL=...   # or --credential-file; keep credentials out of command lines
agentlogin enroll --handle scout@example.com --name laptop

# each sign-in: point the client at the application's login URL
agentlogin login https://app.example.org/auth/agent/login --handle scout@example.com
# -> Signed in to app.example.org as scout@example.com

agentlogin fetch https://app.example.org/api/me --handle scout@example.com   # uses the stored session cookies
```

Library:

```ts
import { AgentLogin, FileKeystore, FileCookieJar } from 'agentlogin';

const handle = 'scout@example.com';
const al = new AgentLogin({ handle, keystore: new FileKeystore(), cookies: FileCookieJar.forHandle(handle) });   // one jar per agent
await al.enroll({ credential: process.env.OWNER_CREDENTIAL!, name: 'server-1' });   // once
const result = await al.signInAt('https://app.example.org/auth/agent/login');
await al.follow(result);                       // completes the application's sign-in; cookies are stored
const me = await al.fetch('https://app.example.org/api/me');
```

If the Issuer requires the agent's owner to approve, `login` prints `The agent's owner must approve this sign-in;
waiting.` on stderr and blocks, polling the Issuer, until the owner approves or refuses or the limit is reached (600 s
by default, `--timeout SECONDS`). A refusal or a timeout exits 1 with the reason. The sign-in is refused when its
callback goes to a host other than the login URL's; name that host with `--site` (and `--accept-host` for further
ones) when the application's callback lives elsewhere.

`signInAt` starts at the application as Section 5.8 describes: it appends `iss` and `login_hint`, keeps the
application's cookies, and takes the Authentication Request the application redirects to. If you already hold an
Authentication Request URL, use `signIn({ authorizationUrl, expectedHost })` (CLI: `--authorization-url --site`).

What it does, by specification section: WebFinger discovery of the handle's Issuer over HTTPS with the fetch
protections of 2.2 (A-1); sends the Authentication Request itself on the JSON path (5.3) so it is the Session Holder
and never sets `deliver_to_session` (A-4); verifies `iss`, the transaction URLs and the client's `redirect_host`
against the site you named before asserting (A-3); signs the assertion with an ES256 key from the keystore (6.3);
answers reviews and waits for Owner approval using `retry_after` (A-5); follows the continue step with the
`transaction_token` and fetches the redirect with a per-host cookie jar, never forwarding `Authorization` (A-6, A-9).
The code-bearing redirect URL is returned from `signIn` for `follow` and is never printed by the CLI.

Keys live in `~/.agentlogin/keys.json` and cookies in `~/.agentlogin/cookies/<hash of the handle>.json`, one jar per
agent: a session one agent obtained is never sent for another, and `Scout@example.com` and `scout@example.com` are
different agents. Files are readable by you only, written atomically, and every change is locked across processes, so
commands running at the same time lose nothing. A lock left by a process that died is taken over; a process that was
suspended long enough to lose its lock refuses to write when it resumes. Set `AGENTLOGIN_HOME` to move them. Nothing secret is printed: not
credentials, keys, cookie values, tokens or the callback URL. `--json` gives machine-readable results and errors
(`{"error": {"code", "message"}}`); the exit status is 0 only on success and 2 for usage errors.

Enrollment never discards a key the Issuer may hold. When the answer to an enrollment request is lost (a timeout, a
dropped connection, a `5xx`), the client asks the Issuer what it has: an active key is kept as active, a key the
Issuer does not know is removed, and when the Issuer cannot be asked the key stays as `pending` and `enroll` fails
with `enrollment_uncertain`. `agentlogin keys` (and `reconcileKeys`) settles pending keys later. Only a definite
refusal (`enrollment_failed`) removes the key. Revoking a key at one Issuer changes the local record for that Issuer
only. `--timeout` bounds the whole sign-in, each request and wait included, so nothing is asserted or continued after
the deadline. A cookie without a `Path` gets the default path of RFC 6265 Section 5.1.4 (the directory of the URL
that set it), not `/`.

The DNS fallback of Section 2.3 needs DNSSEC validation that Node.js does not expose and is not implemented;
`--issuer` / `AGENTLOGIN_ISSUER` pins an Issuer for development or a known deployment (`handle_domains` is still
checked). An operating-system keystore backend is planned.
