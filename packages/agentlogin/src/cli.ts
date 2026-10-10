// Command-line interface. Secrets are never printed: not credentials, private keys, cookie values, tokens, or the
// code-bearing redirect. Results go to stdout, progress and errors to stderr; with --json, errors are JSON on stdout
// as well. Exit status is 0 only when the command succeeded.
import { readFileSync } from 'node:fs';
import { AgentLogin, AgentLoginError } from './client.js';
import { FileCookieJar } from './cookies.js';
import { FileKeystore } from './keystore.js';

const USAGE = `agentlogin: sign a software agent in to web applications (Agent Login protocol)

  agentlogin enroll                      enroll a new key for the handle (needs a credential)
        [--name N]
  agentlogin login <login-url>           sign in at an application, starting from its login URL; iss and login_hint
        [--site HOST] [--no-hint]          are appended (Section 5.8) unless --no-hint; stores the session cookies
        [--deny-review] [--no-follow]
  agentlogin login <url> --authorization-url --site HOST
                                         the same, starting from an Authentication Request URL
  agentlogin fetch <url>                 request with the session cookies stored for that application
        [--method M] [--data D] [--content-type T]
  agentlogin cookies --site HOST         list the cookies stored for an application (names only)
        [--clear]
  agentlogin keys                        list the keys enrolled at the Issuer (needs a credential)
  agentlogin revoke [--kid K]            revoke one key, or every key of the handle (needs a credential)
  agentlogin keygen [--name N]           generate a key without enrolling it; prints the public JWK
  agentlogin whoami                      the Issuer found for the handle, and the local keys

Options for every command:
  --handle H            the Agent Handle (or AGENTLOGIN_HANDLE)
  --issuer URL          use this Issuer instead of WebFinger discovery (or AGENTLOGIN_ISSUER); handle_domains is still checked
  --credential-file F   read the Owner or Delegated Credential from a file (or set AGENTLOGIN_CREDENTIAL)
  --json                machine-readable output; errors as {"error": {"code", "message"}}
  --insecure            development only: http and loopback addresses (or AGENTLOGIN_INSECURE=1)

Files: keys and cookies are kept under ~/.agentlogin (AGENTLOGIN_HOME), readable by you only.`;

const VALUE_FLAGS = new Set(['handle', 'issuer', 'credential', 'credential-file', 'name', 'site', 'method', 'data', 'content-type', 'kid']);
const BOOLEAN_FLAGS = new Set(['json', 'insecure', 'help', 'no-hint', 'deny-review', 'no-follow', 'authorization-url', 'unsafe-skip-host-check', 'clear']);
const COMMANDS = new Set(['enroll', 'login', 'fetch', 'cookies', 'keys', 'revoke', 'keygen', 'whoami']);

class UsageError extends Error {}

function parseArgs(argv: string[]) {
  const flags = new Map<string, string | true>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (!a.startsWith('--')) { positional.push(a); continue; }
    const eq = a.indexOf('=');
    const name = a.slice(2, eq < 0 ? undefined : eq);
    if (BOOLEAN_FLAGS.has(name)) {
      if (eq >= 0) throw new UsageError(`--${name} takes no value`);
      flags.set(name, true);
    } else if (VALUE_FLAGS.has(name)) {
      const value = eq >= 0 ? a.slice(eq + 1) : argv[++i];
      if (value === undefined || (eq < 0 && value.startsWith('--'))) throw new UsageError(`--${name} needs a value`);
      flags.set(name, value);
    } else {
      throw new UsageError(`unknown option --${name}`);
    }
  }
  return { flags, positional };
}

const hostOf = (site: string): string => {
  try {
    return new URL(site.includes('://') ? site : `https://${site}`).host;
  } catch {
    throw new UsageError(`--site is not a host or URL: ${site}`);
  }
};

async function run(argv: string[], flags: Map<string, string | true>, positional: string[]): Promise<void> {
  const cmd = positional[0];
  if (flags.has('help') || !cmd) { console.log(USAGE); return; }
  if (!COMMANDS.has(cmd)) throw new UsageError(`unknown command ${cmd}`);
  const str = (k: string, env?: string) => { const v = flags.get(k); return typeof v === 'string' ? v : env ? process.env[env] || undefined : undefined; };
  const json = flags.has('json');
  const handle = str('handle', 'AGENTLOGIN_HANDLE');
  if (!handle) throw new UsageError('--handle (or AGENTLOGIN_HANDLE) is required');
  const al = new AgentLogin({
    handle,
    keystore: new FileKeystore(),
    cookies: FileCookieJar.forHandle(handle),
    issuer: str('issuer', 'AGENTLOGIN_ISSUER'),
    allowInsecure: process.env.AGENTLOGIN_INSECURE === '1' || flags.has('insecure'),
    log: (m) => console.error(m),
  });
  const credential = (): string => {
    const file = str('credential-file');
    const c = file ? readFileSync(file, 'utf8').trim() : str('credential', 'AGENTLOGIN_CREDENTIAL');
    if (!c) throw new UsageError('a credential is required: set AGENTLOGIN_CREDENTIAL or pass --credential-file');
    return c;
  };
  const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));
  const need = (n: number, usage: string) => { if (positional.length !== n) throw new UsageError(`usage: agentlogin ${usage}`); };

  switch (cmd) {
    case 'enroll': {
      need(1, 'enroll [--name N]');
      const k = await al.enroll({ credential: credential(), name: str('name') });
      if (json) out({ handle: k.handle, issuer: k.issuer, kid: k.kid, status: k.status, expires_at: k.expiresAt });
      else console.log(`Enrolled key ${k.kid} for ${k.handle} at ${k.issuer}`);
      return;
    }
    case 'keygen': {
      need(1, 'keygen [--name N]');
      const k = await al.generateKey(str('name'));
      out({ handle: k.handle, issuer: k.issuer, kid: k.kid, status: k.status, jwk: k.publicJwk });
      return;
    }
    case 'login': {
      need(2, 'login <url> [--site HOST]');
      const url = positional[1]!;
      const site = str('site');
      const common = {
        expectedHost: site ? hostOf(site) : undefined,
        unsafeSkipHostCheck: flags.has('unsafe-skip-host-check'),
        acceptDisclosure: !flags.has('deny-review'),
        onOwnerApproval: () => console.error("The agent's owner must approve this sign-in; waiting."),
      };
      // The URL is the application's login URL (Section 5.8; the default) or, with --authorization-url, the
      // Authentication Request itself, in which case --site names the application.
      const result = flags.has('authorization-url')
        ? await al.signIn({ ...common, authorizationUrl: url })
        : await al.signInAt(url, { ...common, sendIssAndLoginHint: !flags.has('no-hint') });
      const answered = flags.has('no-follow') ? undefined : (await al.follow(result)).status;
      const ok = answered === undefined || answered < 400;
      const summary = { signed_in: answered !== undefined && ok, handle: result.handle, issuer: result.issuer, client_id: result.client.client_id, site: result.client.redirect_host, scopes: result.scopes, site_status: answered };
      if (!ok) throw new AgentLoginError(`${result.client.redirect_host} answered ${answered} to the sign-in callback`, 'callback_failed', answered);
      if (json) out(summary);
      else if (answered === undefined) console.log(`Approved the sign-in to ${result.client.redirect_host} as ${result.handle}; the redirect was not followed (--no-follow), so no session was created.`);
      else console.log(`Signed in to ${result.client.redirect_host} as ${result.handle}`);
      return;
    }
    case 'fetch': {
      need(2, 'fetch <url> [--method M] [--data D]');
      const data = str('data');
      const res = await al.fetch(positional[1]!, { method: str('method') ?? (data !== undefined ? 'POST' : 'GET'), body: data, headers: data !== undefined ? { 'content-type': str('content-type') ?? 'application/json' } : {} });
      const body = await res.text();
      if (json) out({ status: res.status, content_type: res.headers.get('content-type'), location: res.headers.get('location') ?? undefined, body });
      else { console.error(`${res.status} ${res.statusText}`); console.log(body); }
      if (res.status >= 400) process.exitCode = 1;
      return;
    }
    case 'cookies': {
      need(1, 'cookies --site HOST [--clear]');
      const site = str('site');
      if (!site) throw new UsageError('--site is required');
      const host = hostOf(site).replace(/:\d+$/, '');
      if (flags.has('clear')) { await al.cookies.clear(host); if (json) out({ cleared: host }); else console.log(`Cleared cookies for ${host}`); return; }
      const list = (await al.cookies.list(host)).map((c) => ({ name: c.name, path: c.path, secure: c.secure, expires: c.expires ? new Date(c.expires).toISOString() : undefined }));
      if (json) out({ site: host, cookies: list });
      else console.log(list.length ? list.map((c) => `${c.name}  path=${c.path}${c.expires ? `  expires=${c.expires}` : ''}`).join('\n') : `No cookies stored for ${host}`);
      return;
    }
    case 'keys': need(1, 'keys'); out(await al.listKeys(credential())); return;
    case 'revoke': {
      need(1, 'revoke [--kid K]');
      const kid = str('kid');
      await al.revokeKey(credential(), kid);
      if (json) out({ revoked: kid ?? 'all', handle: al.handle });
      else console.log(kid ? `Revoked ${kid}` : `Revoked every key of ${al.handle}`);
      return;
    }
    case 'whoami': {
      need(1, 'whoami');
      const d = await al.discover();
      const keys = (await new FileKeystore().list(al.handle)).map((k) => ({ kid: k.kid, status: k.status, name: k.name, created_at: k.createdAt, expires_at: k.expiresAt }));
      out({ handle: al.handle, issuer: d.issuer, transaction_endpoint: d.metadata.transaction_endpoint, keys });
      return;
    }
  }
  void argv;
}

export async function main(argv: string[]): Promise<void> {
  let json = argv.includes('--json');
  try {
    const { flags, positional } = parseArgs(argv);
    json = flags.has('json');
    await run(argv, flags, positional);
  } catch (e) {
    const code = e instanceof AgentLoginError ? e.code : e instanceof UsageError ? 'usage' : 'error';
    const message = e instanceof Error ? e.message : String(e);
    const transaction = e instanceof AgentLoginError ? e.resource : undefined;
    if (json) console.log(JSON.stringify({ error: { code, message, transaction } }, null, 2));
    else console.error(e instanceof UsageError ? `${message}\n\nRun agentlogin --help for usage.` : `${message}${transaction?.transaction_id ? ` [transaction ${transaction.transaction_id} ${transaction.status}]` : ''}`);
    process.exitCode = e instanceof UsageError ? 2 : 1;
  }
}
