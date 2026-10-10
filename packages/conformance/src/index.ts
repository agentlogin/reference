// Black-box conformance harness for Agent Login issuers (checklist items I-*, Section numbers of the core spec).
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { createHash } from 'node:crypto';
import { AgentClient, rnd } from './agent.js';
import { call, obj, type Res } from './http.js';

export interface HarnessOptions {
  issuer: string;
  /** Bootstrap token: RFC 7591 initial access token and, for the reference issuer, the admin API. */
  adminToken?: string;
  /** Existing Agent to use when the harness cannot create one. */
  handle?: string;
  ownerCredential?: string;
  /** Optional Open Client to exercise Section 4.2: a reachable metadata URL and one of its redirect URIs. */
  openClient?: { clientId: string; redirectUri: string };
  log?: (line: string) => void;
}
export type Outcome = 'pass' | 'fail' | 'skip';
export interface CheckResult { id: string; title: string; outcome: Outcome; detail?: string }
export interface Report { issuer: string; results: CheckResult[]; passed: number; failed: number; skipped: number }

interface Meta { [k: string]: any }
interface RegisteredClient { client_id: string; client_secret: string; redirect_uri: string }

class Harness {
  results: CheckResult[] = [];
  meta!: Meta;
  agent!: AgentClient;
  credential!: string;
  ownerId?: string;
  client!: RegisteredClient; // no cap, no review requirement
  cappedClient?: RegisteredClient; // max_signups_per_owner 1
  constructor(public o: HarnessOptions) {}

  log(s: string) { this.o.log?.(s); }
  record(id: string, title: string, outcome: Outcome, detail?: string) {
    this.results.push({ id, title, outcome, detail });
    this.log(`${outcome.toUpperCase().padEnd(4)} ${id.padEnd(5)} ${title}${detail ? ` — ${detail}` : ''}`);
  }
  /** Runs a check; an assertion failure (thrown Error) records a fail. */
  async check(id: string, title: string, fn: () => Promise<void>) {
    try {
      await fn();
      this.record(id, title, 'pass');
    } catch (e) {
      if (e instanceof Skip) this.record(id, title, 'skip', e.message);
      else this.record(id, title, 'fail', (e as Error).message);
    }
  }

  // ---- helpers -----------------------------------------------------------------------------------
  pkce() {
    const verifier = rnd(32);
    return { verifier, challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url') };
  }
  authUrl(client: RegisteredClient, over: Record<string, string | undefined> = {}, extraPairs: Array<[string, string]> = []) {
    const { verifier, challenge } = this.pkce();
    const params: Record<string, string | undefined> = {
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: client.redirect_uri,
      scope: 'openid email profile',
      state: rnd(),
      nonce: rnd(),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...over,
    };
    const u = new URL(this.meta.authorization_endpoint);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.append(k, v);
    for (const [k, v] of extraPairs) u.searchParams.append(k, v);
    return { url: u.href, verifier, params };
  }
  /** Starts a transaction on the JSON path. */
  async start(client: RegisteredClient = this.client, over: Record<string, string | undefined> = {}) {
    const a = this.authUrl(client, over);
    const r = await call(a.url);
    expect(r.status === 200, `authorize JSON path status ${r.status}: ${r.text.slice(0, 200)}`);
    return { res: r, tx: obj(r.json), verifier: a.verifier, params: a.params };
  }
  async assert(tx: Record<string, any>, agent: AgentClient = this.agent, extra: Record<string, unknown> = {}, mutate = {}) {
    const jws = await agent.assertion(this.o.issuer, tx as never, extra, mutate);
    return call(tx.next.url, { method: 'POST', json: { assertion: jws } });
  }
  async get(tx: Record<string, any>, bearer?: string) {
    return call(tx.url, { headers: bearer ? { authorization: `Bearer ${bearer}` } : {} });
  }
  async cont(nextUrl: string, bearer: string) {
    return call(nextUrl, { headers: { authorization: `Bearer ${bearer}` } });
  }
  /** Full happy path: start, assert with accept_disclosure, continue, exchange. */
  async signIn(client: RegisteredClient = this.client, agent: AgentClient = this.agent, scope = 'openid email profile') {
    const s = await this.start(client, { scope });
    const a = await this.assert(s.tx, agent, { accept_disclosure: true });
    const tx = obj(a.json);
    expect(a.status === 200 && tx.status === 'ready', `assertion → ${a.status} ${tx.status} ${tx.reason ?? ''} ${a.text.slice(0, 200)}`);
    const c = await this.cont(tx.next.url, tx.transaction_token);
    expect(c.status === 200 && typeof obj(c.json).redirect === 'string', `continue → ${c.status} ${c.text.slice(0, 200)}`);
    const redirect = new URL(obj(c.json).redirect);
    const code = redirect.searchParams.get('code')!;
    const token = await this.exchange(client, code, s.verifier);
    return { ...s, tx, redirect, code, token: obj(token.json), tokenRes: token };
  }
  async exchange(client: RegisteredClient, code: string, verifier: string, over: Record<string, string> = {}) {
    const basic = Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString('base64');
    return call(this.meta.token_endpoint, { method: 'POST', headers: { authorization: `Basic ${basic}` }, form: { grant_type: 'authorization_code', code, redirect_uri: client.redirect_uri, code_verifier: verifier, ...over } });
  }
  async admin(path: string, json: unknown, method = 'POST') {
    if (!this.o.adminToken) throw new Skip('needs adminToken');
    const r = await call(`${this.o.issuer}${path}`, { method, headers: { authorization: `Bearer ${this.o.adminToken}` }, json });
    expect(r.status < 300, `${method} ${path} → ${r.status} ${r.text.slice(0, 200)}`);
    return obj(r.json);
  }
  async register(meta: Record<string, unknown>): Promise<RegisteredClient> {
    if (!this.o.adminToken) throw new Skip('needs adminToken for registration');
    const redirect_uri = `https://rp-${rnd(4).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.example/cb`;
    const r = await call(this.meta.registration_endpoint, { method: 'POST', headers: { authorization: `Bearer ${this.o.adminToken}` }, json: { redirect_uris: [redirect_uri], client_name: 'Conformance harness', tos_uri: 'https://rp.example/terms', policy_uri: 'https://rp.example/privacy', token_endpoint_auth_method: 'client_secret_basic', ...meta } });
    expect(r.status === 201, `registration → ${r.status} ${r.text.slice(0, 200)}`);
    const j = obj(r.json);
    return { client_id: j.client_id, client_secret: j.client_secret, redirect_uri };
  }
  async newAgent(ownerId: string, local = `agent-${rnd(4).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`) {
    const domain = (this.meta.handle_domains as string[]).find((d) => !d.startsWith('*.')) ?? 'example.com';
    const handle = `${local}@${domain}`;
    await this.admin('/admin/agents', { handle, owner_id: ownerId, name: 'Conformance agent' });
    const agent = await AgentClient.generate(handle);
    const e = await agent.enroll(this.o.issuer, this.meta.agents_endpoint, this.credential);
    expect(e.proof.status === 200, `enroll/prove → ${e.enroll.status}/${e.proof.status} ${e.proof.text.slice(0, 200)}`);
    return agent;
  }

  // ---- bootstrap ---------------------------------------------------------------------------------
  async bootstrap() {
    const m = await call(`${this.o.issuer}/.well-known/openid-configuration`);
    expect(m.status === 200, `metadata → ${m.status}`);
    this.meta = obj(m.json);
    if (this.o.handle && this.o.ownerCredential) {
      this.credential = this.o.ownerCredential;
      this.agent = await AgentClient.generate(this.o.handle);
      const e = await this.agent.enroll(this.o.issuer, this.meta.agents_endpoint, this.credential);
      expect(e.proof.status === 200, `enroll/prove → ${e.enroll.status}/${e.proof.status} ${e.proof.text.slice(0, 200)}`);
    } else {
      const owner = await this.admin('/admin/owners', { email: `owner-${rnd(4).toLowerCase().replace(/[^a-z0-9]/g, 'x')}@example.com`, name: 'Jane Doe' });
      this.ownerId = owner.owner_id;
      this.credential = owner.credential;
      this.agent = await this.newAgent(this.ownerId!, 'scout');
    }
    this.client = await this.register({});
    this.cappedClient = await this.register({ max_signups_per_owner: 1 });
  }

  // ---- checks ------------------------------------------------------------------------------------
  async run(): Promise<Report> {
    await this.bootstrap();
    const m = this.meta;
    const iss = this.o.issuer;

    await this.check('I-1', 'Metadata contains the REQUIRED members and values of 2.4', async () => {
      for (const k of ['transaction_endpoint', 'agents_endpoint', 'handle_domains', 'agent_key_algs_supported', 'agent_login_versions_supported', 'jwks_uri', 'token_endpoint', 'userinfo_endpoint', 'authorization_endpoint']) expect(m[k] !== undefined, `missing ${k}`);
      expect(m.issuer === iss, 'issuer mismatch');
      expect(m.client_id_metadata_document_supported === true, 'client_id_metadata_document_supported');
      expect(m.authorization_response_iss_parameter_supported === true, 'authorization_response_iss_parameter_supported');
      expect(m.code_challenge_methods_supported?.includes('S256'), 'S256');
      expect(m.id_token_signing_alg_values_supported?.includes('ES256'), 'ES256');
      expect(m.agent_key_algs_supported?.includes('ES256'), 'agent_key_algs_supported ES256');
      for (const s of ['openid', 'email', 'profile', 'owner_profile', 'owner_email']) expect(m.scopes_supported?.includes(s), `scope ${s}`);
      expect(m.token_endpoint_auth_methods_supported?.includes('none') && m.token_endpoint_auth_methods_supported?.includes('client_secret_basic'), 'auth methods');
      expect(m.agent_login_versions_supported?.includes('1.0'), 'versions');
    });
    await this.check('I-2', 'No end_session_endpoint, plain or none; grant_types_supported is authorization_code', async () => {
      expect(m.end_session_endpoint === undefined, 'end_session_endpoint present');
      expect(!m.code_challenge_methods_supported?.includes('plain'), 'plain');
      expect(!m.id_token_signing_alg_values_supported?.includes('none'), 'none');
      expect(JSON.stringify(m.grant_types_supported) === '["authorization_code"]', `grant_types ${JSON.stringify(m.grant_types_supported)}`);
      expect(JSON.stringify(m.response_types_supported) === '["code"]', 'response_types');
    });
    await this.check('I-3', 'Rejects requests without PKCE, with plain, without state/nonce, or with a repeated parameter', async () => {
      const cases: Array<[string, Record<string, string | undefined>, Array<[string, string]>]> = [
        ['no code_challenge', { code_challenge: undefined, code_challenge_method: undefined }, []],
        ['plain', { code_challenge_method: 'plain' }, []],
        ['no state', { state: undefined }, []],
        ['no nonce', { nonce: undefined }, []],
        ['repeated scope', {}, [['scope', 'openid']]],
      ];
      for (const [name, over, extra] of cases) {
        const a = this.authUrl(this.client, over, extra);
        const r = await call(a.url);
        const j = obj(r.json);
        const redirect = typeof j.redirect === 'string' ? new URL(j.redirect) : null;
        const err = j.error ?? redirect?.searchParams.get('error');
        expect(r.status === 400 && err === 'invalid_request', `${name}: ${r.status} ${r.text.slice(0, 160)}`);
        if (redirect) expect(redirect.origin + redirect.pathname === this.client.redirect_uri && redirect.searchParams.get('iss') === iss, `${name}: error redirect target`);
      }
    });
    await this.check('I-4', 'Does not redirect on a mismatched redirect_uri; answers 400 directly', async () => {
      const a = this.authUrl(this.client, { redirect_uri: 'https://attacker.example/cb' });
      const r = await call(a.url);
      expect(r.status === 400 && obj(r.json).error === 'invalid_request' && obj(r.json).redirect === undefined, `${r.status} ${r.text.slice(0, 160)}`);
      const h = await call(a.url, { headers: { accept: 'text/html' } });
      expect(h.status === 400 && !h.headers.get('location'), `html path ${h.status}`);
    });
    await this.check('I-6', 'Refuses owner scopes for an Open Client with invalid_scope', async () => {
      if (!this.o.openClient) throw new Skip('no openClient configured');
      const oc: RegisteredClient = { client_id: this.o.openClient.clientId, client_secret: '', redirect_uri: this.o.openClient.redirectUri };
      const a = this.authUrl(oc, { scope: 'openid email owner_email' });
      const r = await call(a.url);
      const j = obj(r.json);
      const err = j.error ?? (typeof j.redirect === 'string' ? new URL(j.redirect).searchParams.get('error') : undefined);
      expect(r.status === 400 && err === 'invalid_scope', `${r.status} ${r.text.slice(0, 160)}`);
      const ok = await this.start(oc, { scope: 'openid email profile' });
      expect(ok.tx.client?.client_type === 'open' && ok.tx.client?.client_id === oc.client_id, 'open client resolved');
    });
    await this.check('I-7', 'JSON path returns 200 with the resource and session_token; HTML path 303 to a wait page with Link and embedded JSON', async () => {
      const s = await this.start();
      expect(s.tx.status === 'awaiting_agent' && s.tx.next?.action === 'assert' && typeof s.tx.challenge === 'string' && typeof s.tx.session_token === 'string', `json resource ${s.res.text.slice(0, 200)}`);
      expect(s.res.headers.get('cache-control')?.includes('no-store') ?? false, 'no-store');
      const a = this.authUrl(this.client);
      const h = await call(a.url, { headers: { accept: 'text/html' } });
      expect(h.status === 303 && !!h.headers.get('location'), `html path ${h.status}`);
      const cookie = h.headers.get('set-cookie') ?? '';
      expect(/httponly/i.test(cookie) && /samesite=lax/i.test(cookie) && !/domain=/i.test(cookie), `cookie attributes: ${cookie}`);
      const wait = await call(h.headers.get('location')!, { headers: { accept: 'text/html', cookie: cookie.split(';')[0]! } });
      expect(wait.status === 200, `wait page ${wait.status}`);
      expect(/rel="agent-login-transaction"/.test(wait.headers.get('link') ?? ''), 'Link header');
      const mEl = /<script type="application\/json" id="agent-login-transaction">(.*?)<\/script>/s.exec(wait.text);
      expect(!!mEl, 'embedded JSON element');
      const embedded = JSON.parse(mEl![1]!);
      expect(embedded.status === 'awaiting_agent' && embedded.session_token === undefined, 'embedded resource must not carry session_token');
      const csp = wait.headers.get('content-security-policy') ?? '';
      expect(/frame-ancestors 'none'/.test(csp) && /script-src/.test(csp) && !/unsafe-inline[^;]*;?/.test(csp.split('script-src')[1]?.split(';')[0] ?? ''), `CSP: ${csp}`);
    });
    await this.check('I-9', 'Identifiers, challenges and tokens have at least 128 bits', async () => {
      const s = await this.start();
      for (const [k, v] of [['transaction_id', s.tx.transaction_id], ['challenge', s.tx.challenge], ['session_token', s.tx.session_token]] as const) expect(typeof v === 'string' && v.length >= 22, `${k} too short`);
      const a = await this.assert(s.tx, this.agent, { accept_disclosure: true });
      const t = obj(a.json);
      expect(typeof t.transaction_token === 'string' && t.transaction_token.length >= 22, 'transaction_token');
      expect(typeof t.next?.url === 'string' && new URL(t.next.url).pathname.split('/').pop()!.length >= 22, 'continue URL secret');
      const anon = await this.get(s.tx);
      expect(anon.status === 200 && obj(anon.json).transaction_token === undefined && obj(anon.json).session_token === undefined && obj(anon.json).next?.url === undefined, 'GET with the identifier alone reveals a credential or the continue URL');
    });
    await this.check('I-10', 'Every response carries iss, url, status and next; errors on an existing transaction carry status and next', async () => {
      const s = await this.start();
      for (const k of ['iss', 'url', 'status', 'next', 'expires_at', 'client', 'requested_scopes', 'disclosure']) expect(s.tx[k] !== undefined, `missing ${k}`);
      expect(s.tx.iss === iss && s.tx.url.startsWith(m.transaction_endpoint), 'iss/url');
      expect(s.tx.client.redirect_host === new URL(this.client.redirect_uri).host, 'client.redirect_host');
      const bad = await call(s.tx.next.url, { method: 'POST', json: { assertion: 'nonsense' } });
      const j = obj(bad.json);
      expect(bad.status === 400 && j.error === 'invalid_assertion' && j.status === 'awaiting_agent' && j.next?.action === 'assert', `error body ${bad.text.slice(0, 200)}`);
      const unknown = await call(`${m.transaction_endpoint}/${rnd()}`);
      expect(unknown.status === 404 && obj(unknown.json).error === 'invalid_transaction', 'unknown transaction');
    });
    await this.check('I-11', 'Accepts a valid assertion and consumes the challenge', async () => {
      const s = await this.start();
      const a = await this.assert(s.tx, this.agent, { accept_disclosure: true });
      const t = obj(a.json);
      expect(a.status === 200 && t.status === 'ready' && t.challenge === undefined && t.next?.action === 'continue', `${a.status} ${a.text.slice(0, 200)}`);
      const again = await this.assert(s.tx, this.agent, { accept_disclosure: true });
      expect(again.status === 409 && obj(again.json).error === 'assertion_replayed', `replay → ${again.status} ${again.text.slice(0, 120)}`);
    });
    await this.check('I-12', 'Rejects malformed and foreign assertions with the matching error and leaves status and challenge unchanged', async () => {
      const s = await this.start();
      const other = await AgentClient.generate(this.agent.handle); // same handle, unenrolled key
      const cases: Array<[string, () => Promise<Res>, number, string]> = [
        ['wrong aud', () => this.assert(s.tx, this.agent, {}, { payload: { aud: 'https://other.example' } }), 400, 'invalid_assertion'],
        ['wrong txn', () => this.assert(s.tx, this.agent, {}, { payload: { txn: rnd() } }), 400, 'invalid_assertion'],
        ['wrong nonce', () => this.assert(s.tx, this.agent, {}, { payload: { nonce: rnd() } }), 400, 'invalid_assertion'],
        ['expired', () => this.assert(s.tx, this.agent, {}, { iat: Math.floor(Date.now() / 1000) - 1000, exp: Math.floor(Date.now() / 1000) - 500 }), 400, 'invalid_assertion'],
        ['exp too long', () => this.assert(s.tx, this.agent, {}, { exp: Math.floor(Date.now() / 1000) + 3600 }), 400, 'invalid_assertion'],
        ['wrong typ', () => this.assert(s.tx, this.agent, {}, { header: { typ: 'JWT' } }), 400, 'invalid_assertion'],
        ['jwk header', () => this.assert(s.tx, this.agent, {}, { header: { jwk: this.agent.publicJwk } }), 400, 'invalid_assertion'],
        ['sub differs', () => this.assert(s.tx, this.agent, {}, { payload: { sub: 'x@example.com' } }), 400, 'invalid_assertion'],
        ['unknown kid', () => this.assert(s.tx, other), 401, 'unknown_key'],
        ['bad signature', () => this.assert(s.tx, other, {}, { header: { kid: this.agent.kid } }), 401, 'invalid_signature'],
        ['oversize', () => this.assert(s.tx, this.agent, { pad: 'x'.repeat(3000) }), 400, 'invalid_assertion'],
      ];
      for (const [name, fn, status, error] of cases) {
        const r = await fn();
        const j = obj(r.json);
        expect(r.status === status && j.error === error, `${name}: ${r.status} ${j.error} ${j.error_description ?? ''}`);
        expect(j.status === 'awaiting_agent' && j.next?.action === 'assert', `${name}: status/next in error body`);
      }
      const after = obj((await this.get(s.tx)).json);
      expect(after.status === 'awaiting_agent' && after.challenge === s.tx.challenge, 'challenge changed after rejected assertions');
    });
    await this.check('I-13', 'Gates: first visit → awaiting_consent; prompt=none → consent_required; owner scope → awaiting_owner; approval → ready', async () => {
      const fresh = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const s1 = await this.start();
      const a1 = obj((await this.assert(s1.tx, fresh)).json);
      expect(a1.status === 'awaiting_consent' && a1.consent_reason === 'first_visit' && a1.next?.action === 'review', `first visit: ${JSON.stringify(a1).slice(0, 200)}`);
      const s2 = await this.start(this.client, { prompt: 'none' });
      const a2 = obj((await this.assert(s2.tx, fresh)).json);
      expect(a2.status === 'denied' && a2.reason === 'consent_required', `prompt=none: ${a2.status} ${a2.reason}`);
      const c2 = await this.cont(a2.next.url, a2.transaction_token);
      expect(new URL(obj(c2.json).redirect).searchParams.get('error') === 'consent_required', 'redirect error consent_required');
      const s3 = await this.start(this.client, { scope: 'openid email profile owner_email' });
      const a3 = obj((await this.assert(s3.tx, fresh, { accept_disclosure: true })).json);
      expect(a3.status === 'awaiting_owner' && a3.next?.action === 'await_owner' && typeof a3.next.retry_after === 'number', `owner scope: ${a3.status}`);
      const view = await call(`${iss}/owner/transactions/${s3.tx.transaction_id}`, { headers: { authorization: `Bearer ${this.credential}` } });
      expect(view.status === 200 && obj(view.json).client?.redirect_host === new URL(this.client.redirect_uri).host && obj(view.json).handle === fresh.handle, `owner view ${view.status}`);
      const dec = await call(`${iss}/owner/transactions/${s3.tx.transaction_id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${this.credential}` }, json: { decision: 'approve' } });
      expect(dec.status === 200 && obj(dec.json).status === 'ready', `approve → ${dec.status} ${dec.text.slice(0, 120)}`);
      const poll = obj((await this.get(s3.tx, a3.transaction_token)).json);
      expect(poll.status === 'ready' && typeof poll.next?.url === 'string', 'ready after approval');
      const s4 = await this.start(this.client, { scope: 'openid owner_email', prompt: 'none' });
      const a4 = obj((await this.assert(s4.tx, fresh, { accept_disclosure: true })).json);
      expect(a4.status === 'denied' && a4.reason === 'interaction_required', `prompt=none + owner: ${a4.status} ${a4.reason}`);
      const s5 = await this.start(this.client, { scope: 'openid owner_email' });
      const a5 = obj((await this.assert(s5.tx, fresh, { accept_disclosure: true })).json);
      const refuse = await call(`${iss}/owner/transactions/${s5.tx.transaction_id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${this.credential}` }, json: { decision: 'refuse' } });
      expect(a5.status === 'awaiting_owner' && refuse.status === 200 && obj(refuse.json).reason === 'owner_declined', 'refusal → owner_declined');
      const c5 = await this.cont(obj((await this.get(s5.tx, a5.transaction_token)).json).next.url, a5.transaction_token);
      const u5 = new URL(obj(c5.json).redirect);
      expect(u5.searchParams.get('error') === 'access_denied' && u5.searchParams.get('error_description') === 'owner_declined', 'redirect error owner_declined');
    });
    await this.check('I-14', 'transaction_token returned once; review needs it (session binding does not authorise); decision outside awaiting_consent refused', async () => {
      const fresh = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const s = await this.start();
      const a = obj((await this.assert(s.tx, fresh)).json);
      expect(a.status === 'awaiting_consent', 'awaiting_consent');
      const noCred = await call(a.next.url, { method: 'POST', json: { decision: 'allow' } });
      expect(noCred.status === 401 && obj(noCred.json).error === 'invalid_token', `no credential → ${noCred.status}`);
      const sess = await call(a.next.url, { method: 'POST', headers: { authorization: `Bearer ${s.tx.session_token}` }, json: { decision: 'allow' } });
      expect(sess.status === 401, `session_token → ${sess.status}`);
      const got = obj((await this.get(s.tx, a.transaction_token)).json);
      expect(got.transaction_token === undefined, 'GET must not repeat the transaction_token');
      const allow = await call(a.next.url, { method: 'POST', headers: { authorization: `Bearer ${a.transaction_token}` }, json: { decision: 'allow' } });
      expect(allow.status === 200 && obj(allow.json).status === 'ready', `allow → ${allow.status}`);
      const again = await call(a.next.url, { method: 'POST', headers: { authorization: `Bearer ${a.transaction_token}` }, json: { decision: 'allow' } });
      expect(again.status === 400, `decision while ready → ${again.status}`);
    });
    await this.check('I-15', 'A valid Consent Record skips the review; prompt=consent and material change force it', async () => {
      const fresh = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const first = await this.signIn(this.client, fresh, 'openid email');
      expect(first.tx.status === 'ready', 'first sign-in');
      const s = await this.start(this.client, { scope: 'openid email' });
      const a = obj((await this.assert(s.tx, fresh)).json);
      expect(a.status === 'ready', `second sign-in without accept_disclosure → ${a.status} ${a.consent_reason ?? ''}`);
      const s2 = await this.start(this.client, { prompt: 'consent', scope: 'openid email' });
      const a2 = obj((await this.assert(s2.tx, fresh, { accept_disclosure: true })).json);
      expect(a2.status === 'awaiting_consent' && a2.consent_reason === 'prompt_consent', `prompt=consent → ${a2.status} ${a2.consent_reason}`);
      const s3 = await this.start(this.client, { scope: 'openid email profile' });
      const a3 = obj((await this.assert(s3.tx, fresh)).json);
      expect(a3.status === 'awaiting_consent' && a3.consent_reason === 'material_change', `new scope → ${a3.status} ${a3.consent_reason}`);
      const del = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/consents/${encodeURIComponent(this.client.client_id)}`, { method: 'DELETE', headers: { authorization: `Bearer ${this.credential}` } });
      expect(del.status === 204, `consent revocation → ${del.status}`);
      const s4 = await this.start();
      const a4 = obj((await this.assert(s4.tx, fresh)).json);
      expect(a4.status === 'awaiting_consent' && a4.consent_reason === 'first_visit', 'review required after consent revocation');
    });
    await this.check('I-17', 'Continue URL released per 6.5; JSON answers {redirect}; ready continue single use; denied continue repeatable', async () => {
      const s = await this.start();
      const a = obj((await this.assert(s.tx, this.agent, { accept_disclosure: true })).json);
      const asSession = obj((await this.get(s.tx, s.tx.session_token)).json);
      expect(asSession.next?.action === 'continue' && asSession.next.url === undefined, 'continue URL withheld from the Session Holder without deliver_to_session');
      const direct = await this.cont(a.next.url, s.tx.session_token);
      expect(direct.status === 401, `session continue without deliver_to_session → ${direct.status}`);
      const none = await call(a.next.url);
      expect(none.status === 401, `anonymous continue → ${none.status}`);
      const c = await this.cont(a.next.url, a.transaction_token);
      const r = new URL(obj(c.json).redirect);
      expect(c.status === 200 && r.searchParams.get('code') && r.searchParams.get('state') === s.params.state && r.searchParams.get('iss') === iss, `continue → ${c.status} ${c.text.slice(0, 160)}`);
      const twice = await this.cont(a.next.url, a.transaction_token);
      expect(twice.status === 410 && obj(twice.json).error === 'transaction_expired' && obj(twice.json).status === 'completed', `second continue → ${twice.status}`);
      // deliver_to_session path, HTML redirect
      const s2 = await this.start();
      const a2 = obj((await this.assert(s2.tx, this.agent, { accept_disclosure: true, deliver_to_session: true })).json);
      const sess = obj((await this.get(s2.tx, s2.tx.session_token)).json);
      expect(typeof sess.next?.url === 'string', 'continue URL released to the Session Holder with deliver_to_session');
      const html = await call(sess.next.url, { headers: { accept: 'text/html', authorization: `Bearer ${s2.tx.session_token}` } });
      expect((html.status === 302 || html.status === 303) && (html.headers.get('location') ?? '').startsWith(this.client.redirect_uri) && (html.headers.get('cache-control') ?? '').includes('no-store'), `html continue → ${html.status} ${html.headers.get('cache-control')}`);
      expect(a2.transaction_token !== undefined, 'agent still receives a transaction_token');
      // denied path repeatable
      const s3 = await this.start(this.client, { prompt: 'none' });
      const fresh = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const a3 = obj((await this.assert(s3.tx, fresh)).json);
      expect(a3.status === 'denied', 'denied');
      const d1 = await this.cont(a3.next.url, a3.transaction_token);
      const d2 = await this.cont(a3.next.url, a3.transaction_token);
      expect(d1.status === 200 && d2.status === 200, 'denied continue repeatable');
    });
    await this.check('I-19', 'Code single use; wrong verifier, redirect_uri or client → invalid_grant', async () => {
      const r = await this.signIn();
      expect(r.tokenRes.status === 200, `exchange → ${r.tokenRes.status} ${r.tokenRes.text.slice(0, 160)}`);
      const reuse = await this.exchange(this.client, r.code, r.verifier);
      expect(reuse.status === 400 && obj(reuse.json).error === 'invalid_grant', `reuse → ${reuse.status}`);
      const s = await this.signIn();
      const ui = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${s.token.access_token}` } });
      const s2 = await this.start();
      const a2 = obj((await this.assert(s2.tx, this.agent)).json);
      const c2 = new URL(obj((await this.cont(a2.next.url, a2.transaction_token)).json).redirect);
      const badVerifier = await this.exchange(this.client, c2.searchParams.get('code')!, rnd(32));
      expect(badVerifier.status === 400 && obj(badVerifier.json).error === 'invalid_grant', `bad verifier → ${badVerifier.status}`);
      const s3 = await this.start();
      const a3 = obj((await this.assert(s3.tx, this.agent)).json);
      const c3 = new URL(obj((await this.cont(a3.next.url, a3.transaction_token)).json).redirect);
      const wrongClient = await this.exchange(this.cappedClient!, c3.searchParams.get('code')!, s3.verifier);
      expect(wrongClient.status === 400 && obj(wrongClient.json).error === 'invalid_grant', `wrong client → ${wrongClient.status}`);
      const noVerifier = await call(m.token_endpoint, { method: 'POST', headers: { authorization: `Basic ${Buffer.from(`${this.client.client_id}:${this.client.client_secret}`).toString('base64')}` }, form: { grant_type: 'authorization_code', code: c3.searchParams.get('code')!, redirect_uri: this.client.redirect_uri } });
      expect(noVerifier.status === 400 && obj(noVerifier.json).error === 'invalid_grant', `no verifier → ${noVerifier.status}`);
      expect(ui.status === 200, 'userinfo with a fresh token');
    });
    await this.check('I-20', 'Token response shape: Bearer, expires_in, id_token, scope, no refresh_token, no-store', async () => {
      const r = await this.signIn();
      const t = r.token;
      expect(t.token_type === 'Bearer' && typeof t.access_token === 'string' && typeof t.id_token === 'string' && typeof t.scope === 'string' && typeof t.expires_in === 'number' && t.expires_in <= 600, `shape ${JSON.stringify(Object.keys(t))}`);
      expect(t.refresh_token === undefined, 'refresh_token present');
      expect(r.tokenRes.headers.get('cache-control')?.includes('no-store') ?? false, 'no-store');
    });
    await this.check('I-21', 'ID Token: ES256 with kid, iss/aud/nonce, actor_type agent, scope, email = handle, email_verified, exp-iat ≤ 600', async () => {
      const r = await this.signIn();
      const jwks = createRemoteJWKSet(new URL(m.jwks_uri));
      const header = decodeProtectedHeader(r.token.id_token);
      expect(header.alg === 'ES256' && typeof header.kid === 'string' && header.jwk === undefined && header.jku === undefined && header.x5u === undefined && header.x5c === undefined, 'header');
      const { payload } = await jwtVerify(r.token.id_token, jwks, { issuer: iss, audience: this.client.client_id, algorithms: ['ES256'] });
      expect(payload.nonce === r.params.nonce, 'nonce');
      expect(payload.actor_type === 'agent', 'actor_type');
      expect(payload.scope === 'openid email profile', `scope claim ${payload.scope}`);
      expect(payload.email === this.agent.handle && payload.email_verified === true, 'email claims');
      expect(typeof payload.sub === 'string' && payload.sub.length >= 22 && typeof payload.owner_sub === 'string' && typeof payload.preferred_username === 'string', 'profile claims');
      expect(typeof payload.jti === 'string' && payload.exp! - payload.iat! <= 600, 'exp/iat/jti');
      expect(payload.owner_email === undefined && payload.owner_name === undefined, 'owner claims must be omitted');
      const r2 = await this.signIn(this.client, this.agent, 'openid');
      const { payload: p2 } = await jwtVerify(r2.token.id_token, jwks, { issuer: iss, audience: this.client.client_id });
      expect(p2.email === undefined && p2.owner_sub === undefined && p2.actor_type === 'agent', 'ungranted claims omitted');
      expect(p2.sub === payload.sub, 'sub stable');
    });
    await this.check('I-22', 'Owner Claims only with owner_verified_via, after approval or share_owner', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const keys = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys/${encodeURIComponent(fresh.kid)}`, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { permissions: { share_owner: true } } });
      expect(keys.status === 200 && obj(keys.json).permissions?.share_owner === true, `share_owner grant → ${keys.status} ${keys.text.slice(0, 120)}`);
      const r = await this.signIn(this.client, fresh, 'openid email owner_email owner_profile');
      const { payload } = await jwtVerify(r.token.id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss });
      expect(payload.owner_email !== undefined && payload.owner_email_verified === true && typeof payload.owner_verified_via === 'string', `owner claims ${JSON.stringify(payload).slice(0, 200)}`);
    });
    await this.check('I-23', 'UserInfo returns 401 invalid_token after key revocation; sub matches; accepted nowhere else', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const r = await this.signIn(this.client, fresh);
      const ui = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${r.token.access_token}` } });
      const { payload } = await jwtVerify(r.token.id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss });
      expect(ui.status === 200 && obj(ui.json).sub === payload.sub && obj(ui.json).email === fresh.handle, `userinfo ${ui.status} ${ui.text.slice(0, 160)}`);
      const del = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys/${encodeURIComponent(fresh.kid)}`, { method: 'DELETE', headers: { authorization: `Bearer ${this.credential}` } });
      expect(del.status === 204, `revoke → ${del.status}`);
      const after = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${r.token.access_token}` } });
      expect(after.status === 401 && /invalid_token/.test(after.headers.get('www-authenticate') ?? ''), `after revocation → ${after.status} ${after.headers.get('www-authenticate')}`);
      const none = await call(m.userinfo_endpoint);
      expect(none.status === 401, 'no token → 401');
    });
    await this.check('I-24', 'Enrollment validates the JWK strictly and the proof per 7.2; revoked keys cannot re-enroll', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const base = `${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys`;
      const hdr = { authorization: `Bearer ${this.credential}` };
      const jwk = (await AgentClient.generate(fresh.handle)).publicJwk;
      const extra = await call(base, { method: 'POST', headers: hdr, json: { jwk: { ...jwk, use: 'sig' } } });
      expect(extra.status === 400, `extra member → ${extra.status}`);
      const curve = await call(base, { method: 'POST', headers: hdr, json: { jwk: { ...jwk, crv: 'P-384' } } });
      expect(curve.status === 400, `wrong curve → ${curve.status}`);
      const offCurve = await call(base, { method: 'POST', headers: hdr, json: { jwk: { ...jwk, y: jwk.x } } });
      expect(offCurve.status === 400, `point off curve → ${offCurve.status}`);
      const noCred = await call(base, { method: 'POST', json: { jwk } });
      expect(noCred.status === 401, `no credential → ${noCred.status}`);
      const second = await AgentClient.generate(fresh.handle);
      const en = await call(base, { method: 'POST', headers: hdr, json: { jwk: second.publicJwk, name: 'second' } });
      expect(en.status === 201 && obj(en.json).status === 'pending' && typeof obj(en.json).challenge === 'string' && obj(en.json).kid === second.kid, `enroll → ${en.status} ${en.text.slice(0, 160)}`);
      const wrongNonce = await call(obj(en.json).proof_url, { method: 'POST', json: { proof: await second.assertion(iss, { transaction_id: 'x', challenge: rnd() }, {}, { header: { typ: 'agent-login-enrollment+jwt' } }) } });
      expect(wrongNonce.status === 400 && obj(wrongNonce.json).error === 'invalid_assertion', `wrong nonce proof → ${wrongNonce.status} ${wrongNonce.text.slice(0, 120)}`);
      const wrongTyp = await call(obj(en.json).proof_url, { method: 'POST', json: { proof: await second.assertion(iss, { transaction_id: 'x', challenge: obj(en.json).challenge }) } });
      expect(wrongTyp.status === 400, `assertion typ as proof → ${wrongTyp.status}`);
      const ok = await call(obj(en.json).proof_url, { method: 'POST', json: { proof: await second.assertion(iss, { transaction_id: 'x', challenge: obj(en.json).challenge }, {}, { header: { typ: 'agent-login-enrollment+jwt' }, payload: { txn: undefined } }) } });
      expect(ok.status === 200 && obj(ok.json).status === 'active', `valid proof → ${ok.status} ${ok.text.slice(0, 120)}`);
      const list = await call(base, { headers: hdr });
      expect(list.status === 200 && Array.isArray(obj(list.json).keys) && obj(list.json).keys.length === 2, 'list keys');
      const del = await call(`${base}/${encodeURIComponent(second.kid)}`, { method: 'DELETE', headers: hdr });
      const re = await call(base, { method: 'POST', headers: hdr, json: { jwk: second.publicJwk } });
      expect(del.status === 204 && re.status === 400, `re-enroll revoked key → ${re.status}`);
    });
    await this.check('I-26', 'Key revocation denies open transactions (key_revoked), voids unredeemed codes, keeps Consent Records', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      await this.signIn(this.client, fresh); // consent exists now
      const open = await this.start();
      const a = obj((await this.assert(open.tx, fresh)).json);
      expect(a.status === 'ready', 'ready');
      const s2 = await this.start();
      const a2 = obj((await this.assert(s2.tx, fresh)).json);
      const c2 = new URL(obj((await this.cont(a2.next.url, a2.transaction_token)).json).redirect);
      const del = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys`, { method: 'DELETE', headers: { authorization: `Bearer ${this.credential}` } });
      expect(del.status === 204, 'revoke all');
      const after = obj((await this.get(open.tx, a.transaction_token)).json);
      expect(after.status === 'denied' && after.reason === 'key_revoked', `open transaction → ${after.status} ${after.reason}`);
      const ex = await this.exchange(this.client, c2.searchParams.get('code')!, s2.verifier);
      expect(ex.status === 400 && obj(ex.json).error === 'invalid_grant', `unredeemed code → ${ex.status}`);
      const s3 = await this.start();
      const a3 = await this.assert(s3.tx, fresh);
      expect(a3.status === 401 && obj(a3.json).error === 'key_revoked', `assert with revoked key → ${a3.status} ${obj(a3.json).error}`);
      const fresh2 = await AgentClient.generate(fresh.handle);
      const e = await fresh2.enroll(iss, m.agents_endpoint, this.credential);
      expect(e.proof.status === 200, 'new key after revocation');
      const s4 = await this.start();
      const a4 = obj((await this.assert(s4.tx, fresh2)).json);
      expect(a4.status === 'ready', `consent kept across revocation: ${a4.status} ${a4.consent_reason ?? ''}`);
    });
    await this.check('I-27', 'Account disable denies open and later transactions (access_denied), invalidates tokens; re-enable preserves counters', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const r = await this.signIn(this.client, fresh);
      const open = await this.start();
      const a = obj((await this.assert(open.tx, fresh)).json);
      const acct = `${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/accounts/${encodeURIComponent(this.client.client_id)}`;
      const dis = await call(acct, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'disabled' } });
      expect(dis.status === 200 && obj(dis.json).status === 'disabled', `disable → ${dis.status}`);
      const after = obj((await this.get(open.tx, a.transaction_token)).json);
      expect(after.status === 'denied' && after.reason === 'access_denied', `open → ${after.status} ${after.reason}`);
      const later = obj((await this.assert((await this.start()).tx, fresh)).json);
      expect(later.status === 'denied' && later.reason === 'access_denied', `later → ${later.status}`);
      const ui = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${r.token.access_token}` } });
      expect(ui.status === 401, `userinfo → ${ui.status}`);
      const other = obj((await this.assert((await this.start(this.cappedClient!)).tx, fresh, { accept_disclosure: true })).json);
      expect(other.status === 'ready', 'other client unaffected');
      const en = await call(acct, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'enabled' } });
      expect(en.status === 200 && obj(en.json).sign_in_count === 1 && obj(en.json).status === 'enabled', `re-enable → ${en.text.slice(0, 160)}`);
      const list = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/accounts`, { headers: { authorization: `Bearer ${this.credential}` } });
      expect(list.status === 200 && Array.isArray(obj(list.json).accounts), 'list accounts');
    });
    await this.check('I-28', 'Per-owner cap counts Accounts ever created plus in-flight transactions; signup_limit_reached', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const owner = await this.admin('/admin/owners', { email: `capped-${rnd(3).toLowerCase().replace(/[^a-z0-9]/g, 'x')}@example.com` });
      const saved = this.credential;
      this.credential = owner.credential;
      try {
        const a1 = await this.newAgent(owner.owner_id);
        const a2 = await this.newAgent(owner.owner_id);
        const inflight = await this.start(this.cappedClient!);
        const i = obj((await this.assert(inflight.tx, a1, { accept_disclosure: true })).json);
        expect(i.status === 'ready', 'first agent passes the cap');
        const second = obj((await this.assert((await this.start(this.cappedClient!)).tx, a2, { accept_disclosure: true })).json);
        expect(second.status === 'denied' && second.reason === 'signup_limit_reached', `second agent while first in flight → ${second.status} ${second.reason}`);
        const c = await this.cont(i.next.url, i.transaction_token);
        expect(new URL(obj((await this.cont(second.next.url, second.transaction_token)).json).redirect).searchParams.get('error') === 'signup_limit_reached', 'redirect error');
        expect(c.status === 200, 'first completes');
        const again = obj((await this.assert((await this.start(this.cappedClient!)).tx, a1)).json);
        expect(again.status === 'ready', `existing account signs in regardless of the cap: ${again.status}`);
        const dis = await call(`${m.agents_endpoint}/${encodeURIComponent(a1.handle)}/accounts/${encodeURIComponent(this.cappedClient!.client_id)}`, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'disabled' } });
        expect(dis.status === 200, 'disable');
        const still = obj((await this.assert((await this.start(this.cappedClient!)).tx, a2, { accept_disclosure: true })).json);
        expect(still.status === 'denied' && still.reason === 'signup_limit_reached', 'disabled account still counts');
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-33', 'session_token accepted as Bearer on the resource; continue answers only to the credential that released it', async () => {
      const s = await this.start();
      const g = await this.get(s.tx, s.tx.session_token);
      expect(g.status === 200 && obj(g.json).status === 'awaiting_agent', `GET with session_token → ${g.status}`);
      const bad = await this.get(s.tx, rnd(32));
      expect(bad.status === 401 && obj(bad.json).error === 'invalid_token' && obj(bad.json).status === 'awaiting_agent', `GET with a wrong bearer → ${bad.status} ${bad.text.slice(0, 120)}`);
      const a = obj((await this.assert(s.tx, this.agent, { accept_disclosure: true })).json);
      const wrong = await this.cont(a.next.url, rnd(32));
      expect(wrong.status === 401, `continue with a wrong bearer → ${wrong.status}`);
      const badSecret = await this.cont(a.next.url.replace(/[^/]+$/, rnd(32)), a.transaction_token);
      expect(badSecret.status === 404, `continue with a wrong secret → ${badSecret.status}`);
    });
    await this.check('I-37', 'Terminal transactions stay readable with 200; POST to a terminal transaction → 410', async () => {
      const r = await this.signIn();
      const g = await this.get(r.tx, r.tx.transaction_token);
      expect(g.status === 200 && obj(g.json).status === 'completed' && obj(g.json).next?.action === 'none', `GET completed → ${g.status} ${g.text.slice(0, 120)}`);
      const post = await call(`${r.tx.url}/assertion`, { method: 'POST', json: { assertion: await this.agent.assertion(iss, { transaction_id: r.tx.transaction_id, challenge: rnd() }) } });
      expect(post.status === 410 && obj(post.json).error === 'transaction_expired' && obj(post.json).status === 'completed', `POST after completion → ${post.status} ${post.text.slice(0, 120)}`);
    });
    await this.check('M-1', 'Delegated Credential: bound to its handle, cannot grant share_owner, cannot re-enable an Account', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const sibling = await this.newAgent(this.ownerId);
      const d = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: fresh.handle });
      const hdr = { authorization: `Bearer ${d.credential}` };
      const own = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys`, { headers: hdr });
      expect(own.status === 200, `own keys → ${own.status}`);
      const sib = await call(`${m.agents_endpoint}/${encodeURIComponent(sibling.handle)}/keys`, { headers: hdr });
      expect(sib.status === 404, `sibling keys → ${sib.status}`);
      const perm = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys/${encodeURIComponent(fresh.kid)}`, { method: 'PATCH', headers: hdr, json: { name: 'x', permissions: { share_owner: true } } });
      expect(perm.status === 403 && obj(perm.json).error === 'insufficient_permission', `share_owner via delegated → ${perm.status}`);
      const k = obj((await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys/${encodeURIComponent(fresh.kid)}`, { headers: hdr })).json);
      expect(k.permissions?.share_owner === false && k.name !== 'x', 'refused PATCH changed nothing');
      await this.signIn(this.client, fresh);
      const acct = `${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/accounts/${encodeURIComponent(this.client.client_id)}`;
      const dis = await call(acct, { method: 'PATCH', headers: hdr, json: { status: 'disabled' } });
      expect(dis.status === 200, `delegated disable → ${dis.status}`);
      const en = await call(acct, { method: 'PATCH', headers: hdr, json: { status: 'enabled' } });
      expect(en.status === 403, `delegated re-enable → ${en.status}`);
    });

    const passed = this.results.filter((r) => r.outcome === 'pass').length;
    const failed = this.results.filter((r) => r.outcome === 'fail').length;
    const skipped = this.results.filter((r) => r.outcome === 'skip').length;
    return { issuer: iss, results: this.results, passed, failed, skipped };
  }
}

class Skip extends Error {}
function expect(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message);
}

export async function runConformance(o: HarnessOptions): Promise<Report> {
  return new Harness(o).run();
}
export { AgentClient };
