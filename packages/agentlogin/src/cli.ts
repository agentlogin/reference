// Command-line interface. Secrets (credentials, keys, cookies, the code-bearing redirect) are never printed.
import { AgentLogin, AgentLoginError } from './client.js';
import { FileCookieJar } from './cookies.js';
import { FileKeystore } from './keystore.js';

const USAGE = `agentlogin: sign a software agent in to web applications (Agent Login protocol)

  agentlogin enroll  --handle H --credential C [--name N]        enroll a new key (Owner or Delegated Credential)
  agentlogin keygen  --handle H [--name N]                       generate a key without enrolling (prints the public JWK)
  agentlogin login   <login-url> --handle H                      sign in at an application, starting from its login URL
                     [--site URL] [--no-hint] [--deny-review]    (iss and login_hint are appended unless --no-hint);
                     [--no-follow] [--json]                      stores the application's session cookies
  agentlogin login   <url> --authorization-url --handle H --site URL
                                                                 the same, starting from an Authentication Request URL
  agentlogin fetch   <url> --handle H [--method M] [--data D]    request with the stored session cookies for that site
  agentlogin cookies --handle H --site URL [--clear]             show (as a Cookie header) or clear a site's cookies
  agentlogin keys    --handle H --credential C                   list keys enrolled at the Issuer
  agentlogin revoke  --handle H --credential C [--kid K]         revoke one key, or every key of the handle
  agentlogin whoami  --handle H                                  discovery result and local keys

Environment: AGENTLOGIN_HANDLE, AGENTLOGIN_CREDENTIAL, AGENTLOGIN_ISSUER (pin the Issuer instead of WebFinger),
AGENTLOGIN_HOME (default ~/.agentlogin), AGENTLOGIN_INSECURE=1 (development: http and loopback).`;

function parseArgs(argv: string[]) {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { flags.set(a.slice(2), next); i += 1; }
      else flags.set(a.slice(2), true);
    } else positional.push(a);
  }
  return { flags, positional };
}

export async function main(argv: string[]): Promise<void> {
  const { flags, positional } = parseArgs(argv);
  const cmd = positional[0];
  if (!cmd || flags.has('help')) { console.log(USAGE); return; }
  const str = (k: string, env?: string) => { const v = flags.get(k); return typeof v === 'string' ? v : env ? process.env[env] : undefined; };
  const handle = str('handle', 'AGENTLOGIN_HANDLE');
  if (!handle) throw new Error('--handle (or AGENTLOGIN_HANDLE) is required');
  const al = new AgentLogin({
    handle,
    keystore: new FileKeystore(),
    cookies: new FileCookieJar(),
    issuer: str('issuer', 'AGENTLOGIN_ISSUER'),
    allowInsecure: process.env.AGENTLOGIN_INSECURE === '1' || flags.get('insecure') === true,
    log: (m) => console.error(m),
  });
  const credential = () => { const c = str('credential', 'AGENTLOGIN_CREDENTIAL'); if (!c) throw new Error('--credential (or AGENTLOGIN_CREDENTIAL) is required'); return c; };
  const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));
  try {
    switch (cmd) {
      case 'enroll': {
        const k = await al.enroll({ credential: credential(), name: str('name') });
        if (flags.has('json')) out({ handle: k.handle, issuer: k.issuer, kid: k.kid, status: k.status });
        else console.log(`Enrolled key ${k.kid} for ${k.handle} at ${k.issuer}`);
        return;
      }
      case 'keygen': {
        const k = await al.generateKey(str('name'));
        out({ handle: k.handle, issuer: k.issuer, kid: k.kid, status: k.status, jwk: k.publicJwk });
        return;
      }
      case 'login': {
        const url = positional[1];
        if (!url) throw new Error('usage: agentlogin login <url> --handle H [--site URL]');
        const site = str('site');
        const common = {
          expectedHost: site ? new URL(site.includes('://') ? site : `https://${site}`).host : undefined,
          unsafeSkipHostCheck: flags.get('unsafe-skip-host-check') === true,
          acceptDisclosure: flags.get('deny-review') !== true,
          onOwnerApproval: () => console.error("The agent's owner must approve this sign-in; waiting."),
        };
        // The URL is either the application's login URL (Section 5.8; the default) or, with --authorization-url, the
        // Authentication Request itself, in which case --site names the application.
        const result = flags.get('authorization-url') === true
          ? await al.signIn({ ...common, authorizationUrl: url })
          : await al.signInAt(url, { ...common, sendIssAndLoginHint: flags.get('no-hint') !== true });
        let answered: number | undefined;
        if (flags.get('no-follow') !== true) answered = (await al.follow(result)).status;
        const ok = answered === undefined || answered < 400;
        if (flags.has('json')) out({ signed_in: ok, handle: result.handle, issuer: result.issuer, client_id: result.client.client_id, site: result.client.redirect_host, scopes: result.scopes, site_status: answered });
        else if (answered === undefined) console.log(`Sign-in for ${result.client.redirect_host} approved as ${result.handle}; the redirect was not followed (--no-follow).`);
        else if (ok) console.log(`Signed in to ${result.client.redirect_host} as ${result.handle}`);
        if (!ok) throw new Error(`${result.client.redirect_host} answered ${answered} to the sign-in callback`);
        return;
      }
      case 'fetch': {
        const url = positional[1];
        if (!url) throw new Error('usage: agentlogin fetch <url> --handle H');
        const res = await al.fetch(url, { method: str('method') ?? 'GET', body: str('data'), headers: str('data') ? { 'content-type': str('content-type') ?? 'application/json' } : {} });
        console.error(`${res.status} ${res.statusText}`);
        console.log(await res.text());
        return;
      }
      case 'cookies': {
        const site = str('site');
        if (!site) throw new Error('--site is required');
        const u = new URL(site.includes('://') ? site : `https://${site}`);
        if (flags.get('clear') === true) { await al.cookies.clear(u.hostname); console.log(`Cleared cookies for ${u.hostname}`); return; }
        console.log((await al.cookies.header(u)) ?? '');
        return;
      }
      case 'keys': out(await al.listKeys(credential())); return;
      case 'revoke': {
        const kid = str('kid');
        await al.revokeKey(credential(), kid);
        console.log(kid ? `Revoked ${kid}` : `Revoked every key of ${handle}`);
        return;
      }
      case 'whoami': {
        const d = await al.discover();
        const keys = (await new FileKeystore().list(al.handle)).map((k) => ({ kid: k.kid, status: k.status, name: k.name, created_at: k.createdAt }));
        out({ handle: al.handle, issuer: d.issuer, transaction_endpoint: d.metadata.transaction_endpoint, keys });
        return;
      }
      default:
        throw new Error(`unknown command ${cmd}\n\n${USAGE}`);
    }
  } catch (e) {
    if (e instanceof AgentLoginError) {
      const r = e.resource;
      throw new Error(`${e.message}${r ? ` [transaction ${r.transaction_id} ${r.status}]` : ''}`);
    }
    throw e;
  }
}
