// Black-box conformance harness for Agent Login issuers (checklist items I-*, Section numbers of the core spec).
import { calculateJwkThumbprint, createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import { AgentClient, rnd } from './agent.js';
import { call, callContext, obj, type CallContext, type Exchange, type Res } from './http.js';
import { concurrentAccessTokens, redirectMatches, validateMetadata, validateForbiddenMetadata } from './validation.js';

export interface HarnessOptions {
  issuer: string;
  /** Bootstrap token: RFC 7591 initial access token and, for the reference issuer, the admin API. */
  adminToken?: string;
  /** Existing Agent to use when the harness cannot create one. */
  handle?: string;
  /** Owner Credential of that Agent's Owner, obtained in a session that satisfies Section 6.6 (passkey, oidc, domain, or email plus a factor). */
  ownerCredential?: string;
  /**
   * I-45, with `handle` and `ownerCredential`: a second Owner Credential of the same Owner, obtained through the
   * issuer's one-time-code (email) sign-in alone. It must neither approve a transaction nor grant `share_owner`.
   */
  emailOnlyOwnerCredential?: string;
  /**
   * I-45, with `adminToken`: signs the Owner with this address in through the issuer's one-time-code (email) sign-in,
   * reading the code from wherever the issuer delivered it, and returns the Owner Credential that sign-in issued.
   */
  ownerEmailSignIn?: (email: string) => Promise<string>;
  /** With `handle` and `ownerCredential` and no `adminToken`: a Registered Client that already exists at the issuer. */
  client?: { clientId: string; clientSecret: string; redirectUri: string };
  /** Optional Open Client to exercise Section 4.2: a reachable metadata URL and one of its redirect URIs. Also the client of existing-agent mode when no Registered Client is given. */
  openClient?: { clientId: string; redirectUri: string };
  /**
   * I-39: reachable Client ID Metadata Documents the issuer must refuse (Sections 3.2, 4.2), for example one stating
   * `id_token_signed_response_alg` `RS256`. Each must answer `400` `invalid_request` directly.
   */
  invalidOpenClients?: Array<{ name: string; clientId: string; redirectUri: string }>;
  /**
   * I-45, I-48: Issuer Identifier of a Relay whose metadata the issuer under test can fetch (Section 4.4), served at
   * `{relayIssuer}/.well-known/openid-configuration` with `issuer` and `op_policy_uri`. Use a domain name, not an IP
   * literal, so that look-alike hosts can be formed.
   */
  relayIssuer?: string;
  log?: (line: string) => void;
}
export type Outcome = 'pass' | 'fail' | 'skip';
export interface CheckResult { id: string; title: string; outcome: Outcome; detail?: string }
export interface Report { issuer: string; results: CheckResult[]; passed: number; failed: number; skipped: number }

interface Meta { [k: string]: any }
interface RegisteredClient { client_id: string; client_secret: string; redirect_uri: string }
/** What I-49 keeps of every exchange of the run: which check made it and the two headers it audits. */
interface Seen { check: string; method: string; url: string; status: number; cacheControl: string | null; allowCredentials: string | null; location: string | null }
const slug = (n = 4) => rnd(n).toLowerCase().replace(/[^a-z0-9]/g, 'x');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

class Harness {
  results: CheckResult[] = [];
  meta!: Meta;
  agent!: AgentClient;
  credential!: string;
  ownerId?: string;
  ownerEmail?: string;
  client!: RegisteredClient; // no cap, no review requirement
  cappedClient?: RegisteredClient; // max_signups_per_owner 1
  /** Every exchange of the run, for the audit of I-49. */
  seen: Seen[] = [];
  current = 'bootstrap';
  /** Keys this run itself enrolled on the operator's existing Agent: exactly these are revoked afterwards. */
  private enrolledHere = new Set<string>();
  cx: CallContext = {
    seen: (x: Exchange) => {
      if (this.o.handle && this.meta && x.method === 'POST' && x.res.status === 201 && x.url === `${this.meta.agents_endpoint}/${encodeURIComponent(this.o.handle)}/keys`) {
        const kid = obj(x.res.json).kid;
        if (typeof kid === 'string') this.enrolledHere.add(kid);
      }
      this.seen.push({ check: this.current, method: x.method, url: x.url, status: x.res.status, cacheControl: x.res.headers.get('cache-control'), allowCredentials: x.res.headers.get('access-control-allow-credentials'), location: x.res.headers.get('location') });
    },
  };
  constructor(public o: HarnessOptions) {}

  log(s: string) { this.o.log?.(s); }
  record(id: string, title: string, outcome: Outcome, detail?: string) {
    this.results.push({ id, title, outcome, detail });
    this.log(`${outcome.toUpperCase().padEnd(4)} ${id.padEnd(5)} ${title}${detail ? ` — ${detail}` : ''}`);
  }
  /** Runs a check; an assertion failure (thrown Error) records a fail. */
  async check(id: string, title: string, fn: () => Promise<void>) {
    this.current = id;
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
    // Owner scopes exist for Registered Clients only (Section 4.1): with an Open Client as the harness's client the check cannot run.
    if (!client.client_secret && /\bowner_/.test(over.scope ?? '')) throw new Skip('owner scopes need a Registered Client');
    const a = this.authUrl(client, over);
    const r = await call(a.url);
    expect(r.status === 200, `authorize JSON path status ${r.status}: ${r.text.slice(0, 200)}`);
    return { res: r, tx: obj(r.json), verifier: a.verifier, params: a.params };
  }
  async assert(tx: Record<string, any>, agent: AgentClient = this.agent, extra: Record<string, unknown> = {}, mutate = {}) {
    const jws = await agent.assertion(this.o.issuer, tx as never, extra, mutate);
    const r = await call(tx.next.url, { method: 'POST', json: { assertion: jws } });
    if (obj(r.json).status === 'awaiting_owner') this.awaitingOwner.add(tx.transaction_id);
    return r;
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
    const form = { grant_type: 'authorization_code', code, redirect_uri: client.redirect_uri, code_verifier: verifier, ...over };
    if (!client.client_secret) return call(this.meta.token_endpoint, { method: 'POST', form: { client_id: client.client_id, ...form } }); // an Open Client does not authenticate
    const basic = Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString('base64');
    return call(this.meta.token_endpoint, { method: 'POST', headers: { authorization: `Basic ${basic}` }, form });
  }
  async admin(path: string, json: unknown, method = 'POST') {
    if (!this.o.adminToken) throw new Skip('needs adminToken');
    const r = await call(`${this.o.issuer}${path}`, { method, headers: { authorization: `Bearer ${this.o.adminToken}` }, json });
    expect(r.status < 300, `${method} ${path} → ${r.status} ${r.text.slice(0, 200)}`);
    return obj(r.json);
  }
  /** A sign-in taken up to the code: started, asserted, continued, not redeemed. */
  async codeFor(client: RegisteredClient = this.client, agent: AgentClient = this.agent): Promise<{ code: string; verifier: string }> {
    const s = await this.start(client);
    const a = obj((await this.assert(s.tx, agent, { accept_disclosure: true })).json);
    expect(a.status === 'ready', `assertion → ${a.status} ${a.reason ?? ''}`);
    const c = await this.cont(a.next.url, a.transaction_token);
    expect(c.status === 200 && typeof obj(c.json).redirect === 'string', `continue → ${c.status}`);
    return { code: new URL(obj(c.json).redirect).searchParams.get('code')!, verifier: s.verifier };
  }
  /** Brings a transaction to its end as its Owner and Agent would: approve, allow, continue. Returns the final resource. */
  async driveToEnd(tx: Record<string, any>, token: string, ownerCredential: string): Promise<Record<string, any>> {
    let cur = tx;
    for (let i = 0; i < 6; i += 1) {
      if (cur.status === 'awaiting_owner') {
        const d = await call(`${this.o.issuer}/owner/transactions/${cur.transaction_id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${ownerCredential}` }, json: { decision: 'approve' } });
        expect(d.status === 200, `Owner approval → ${d.status} ${d.text.slice(0, 120)}`);
        this.awaitingOwner.delete(cur.transaction_id);
        cur = obj((await this.get(cur, token)).json);
      } else if (cur.status === 'awaiting_consent') {
        cur = obj((await call(cur.next.url, { method: 'POST', headers: { authorization: `Bearer ${token}` }, json: { decision: 'allow' } })).json);
      } else return cur;
    }
    return cur;
  }
  /** The client with `max_signups_per_owner` 1; checks that need it are skipped when the harness cannot register one. */
  capped(): RegisteredClient {
    if (!this.cappedClient) throw new Skip('needs adminToken for registration');
    return this.cappedClient;
  }
  async register(meta: Record<string, unknown>): Promise<RegisteredClient> {
    if (!this.o.adminToken) throw new Skip('needs adminToken for registration');
    const redirect_uri = `https://rp-${slug()}.example/cb`;
    const r = await call(this.meta.registration_endpoint, { method: 'POST', headers: { authorization: `Bearer ${this.o.adminToken}` }, json: { redirect_uris: [redirect_uri], client_name: 'Conformance harness', tos_uri: 'https://rp.example/terms', policy_uri: 'https://rp.example/privacy', token_endpoint_auth_method: 'client_secret_basic', ...meta } });
    expect(r.status === 201, `registration → ${r.status} ${r.text.slice(0, 200)}`);
    const j = obj(r.json);
    return { client_id: j.client_id, client_secret: j.client_secret, redirect_uri };
  }
  /** A new Owner with an Owner Credential from a session that satisfies Section 6.6, stated to the bootstrap API with the matching `verified_via`. */
  async newOwner(prefix: string): Promise<{ owner_id: string; credential: string; email: string }> {
    const email = `${prefix}-${slug()}@example.com`;
    const o = await this.admin('/admin/owners', { email, name: 'Jane Doe', verified_via: 'passkey', session_auth: 'passkey' });
    return { owner_id: o.owner_id, credential: o.credential, email };
  }
  async newAgent(ownerId: string, local = `agent-${slug()}`) {
    const domain = (this.meta.handle_domains as string[]).find((d) => !d.startsWith('*.')) ?? 'example.com';
    const handle = `${local}@${domain}`;
    await this.admin('/admin/agents', { handle, owner_id: ownerId, name: 'Conformance agent' });
    const agent = await AgentClient.generate(handle);
    const e = await agent.enroll(this.o.issuer, this.meta.agents_endpoint, this.credential);
    expect(e.proof.status === 200, `enroll/prove → ${e.enroll.status}/${e.proof.status} ${e.proof.text.slice(0, 200)}`);
    return agent;
  }

  /** I-45: an Owner Credential of the harness's Owner from the issuer's one-time-code sign-in, when the operator can supply one. */
  async emailOnlyCredential(): Promise<string | undefined> {
    if (this.o.handle && this.o.ownerCredential) return this.o.emailOnlyOwnerCredential;
    if (this.o.ownerEmailSignIn && this.ownerEmail) return this.o.ownerEmailSignIn(this.ownerEmail);
    return undefined;
  }
  /** The operator's Relay (Section 4.4) with the `op_policy_uri` its metadata publishes; undefined when none is configured. */
  async relay(): Promise<{ issuer: string; policy: string } | undefined> {
    if (!this.o.relayIssuer) return undefined;
    const issuer = this.o.relayIssuer.replace(/\/+$/, '');
    const r = await call(`${issuer}/.well-known/openid-configuration`);
    const policy = obj(r.json).op_policy_uri;
    expect(r.status === 200 && obj(r.json).issuer === issuer && typeof policy === 'string' && policy.length > 0, `relayIssuer metadata must state issuer and op_policy_uri: ${r.status} ${r.text.slice(0, 160)}`);
    return { issuer, policy };
  }
  /**
   * Sections 6.6 and 7.8, through the Owner approval API: `weak`, a valid Owner Credential of the Agent's Owner from a
   * session that does not qualify, can neither approve, refuse nor grant `share_owner`, and changes nothing; the
   * harness's own Owner Credential, from a qualifying session, then approves. `exact` also pins the reference issuer's
   * answer (403 `insufficient_permission`); the specification names no status for these refusals.
   */
  async approvalRule(weak: string, what: string, agent: AgentClient, exact = false) {
    const m = this.meta;
    const keys = `${m.agents_endpoint}/${encodeURIComponent(agent.handle)}/keys`;
    const asWeak = { authorization: `Bearer ${weak}` };
    const asOwner = { authorization: `Bearer ${this.credential}` };
    const valid = await call(keys, { headers: asWeak });
    expect(valid.status === 200 && Array.isArray(obj(valid.json).keys), `${what} must be a valid Owner Credential of the Agent's Owner, or its refusals prove nothing: List keys → ${valid.status}`);
    const refused = (name: string, r: Res) =>
      expect(exact ? r.status === 403 && obj(r.json).error === 'insufficient_permission' : r.status >= 400 && r.status < 500, `${name} with ${what} → ${r.status} ${obj(r.json).error ?? ''}`);
    const s = await this.start(this.client, { scope: 'openid email owner_email' });
    const a = obj((await this.assert(s.tx, agent, { accept_disclosure: true })).json);
    expect(a.status === 'awaiting_owner', `owner scope → ${a.status} ${a.reason ?? ''}`);
    const decision = `${this.o.issuer}/owner/transactions/${s.tx.transaction_id}/decision`;
    for (const d of ['approve', 'refuse']) {
      refused(`decision ${d}`, await call(decision, { method: 'POST', headers: asWeak, json: { decision: d } }));
      const now = obj((await this.get(s.tx, a.transaction_token)).json).status;
      expect(now === 'awaiting_owner', `status after the refused ${d} with ${what}: ${now}`);
    }
    const keyUrl = `${keys}/${encodeURIComponent(agent.kid)}`;
    refused('share_owner grant', await call(keyUrl, { method: 'PATCH', headers: asWeak, json: { permissions: { share_owner: true } } }));
    const k = await call(keyUrl, { headers: asOwner });
    expect(k.status === 200 && obj(k.json).permissions?.share_owner === false, `share_owner after the refused grant with ${what}: ${k.status} ${obj(k.json).permissions?.share_owner}`);
    const again = obj((await this.assert((await this.start(this.client, { scope: 'openid email owner_email' })).tx, agent, { accept_disclosure: true })).json);
    expect(again.status === 'awaiting_owner', `a sign-in with an Owner scope after the refused grant must still wait for the Owner: ${again.status}`);
    const ok = await call(decision, { method: 'POST', headers: asOwner, json: { decision: 'approve' } });
    expect(ok.status === 200 && obj(ok.json).status === 'ready', `approval from a qualifying session → ${ok.status} ${obj(ok.json).status ?? obj(ok.json).error ?? ''}`);
    expect(obj((await this.get(s.tx, a.transaction_token)).json).status === 'ready', 'the transaction is ready after the approval from a qualifying session');
  }

  // ---- bootstrap ---------------------------------------------------------------------------------
  /** Transactions this run left waiting for the Owner; refused at the end so that nobody is asked to approve a test. */
  private awaitingOwner = new Set<string>();

  async bootstrap(): Promise<boolean> {
    const existing = Boolean(this.o.handle && this.o.ownerCredential);
    if (!this.o.adminToken && !existing) throw new Error('the harness needs an admin token, or an existing handle with its Owner Credential');
    // Everything that can be decided from the options is decided before the issuer or the operator's Agent is touched.
    if (!this.o.adminToken && !this.o.client && !this.o.openClient) throw new Error('without an admin token the harness needs a client: a Registered Client (client) or an Open Client (openClient)');
    for (const [name, c] of [['client', this.o.client], ['openClient', this.o.openClient]] as const) {
      if (c && (!c.clientId || !URL.canParse(c.redirectUri))) throw new Error(`${name}: a client identifier and an absolute redirect URI are both required`);
    }
    if (this.o.client && !this.o.client.clientSecret) throw new Error('client: a Registered Client needs its secret (use openClient for a client without one)');
    const m = await call(`${this.o.issuer}/.well-known/openid-configuration`);
    expect(m.status === 200, `metadata → ${m.status}`);
    this.meta = obj(m.json);
    await this.check('I-1', 'Metadata contains the REQUIRED members and values of 2.4', async () => {
      expect(m.json !== null && typeof m.json === 'object' && !Array.isArray(m.json), 'metadata must be a JSON object');
      expect(m.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() === 'application/json', 'metadata must have Content-Type application/json');
      validateMetadata(this.meta, this.o.issuer, Boolean(this.o.adminToken));
    });
    await this.check('I-2', 'Only authorization_code grants; no end_session_endpoint, plain PKCE, none or RS256 signing algorithms', async () => {
      validateForbiddenMetadata(this.meta);
    });
    // Invalid endpoints must never receive the operator's credentials. Return the discovery failures as a report
    // before enrollment, registration or transaction creation can run against malformed metadata.
    if (this.results.some((r) => r.outcome === 'fail')) return false;
    if (existing) {
      this.credential = this.o.ownerCredential!;
      const listed = await call(`${this.meta.agents_endpoint}/${encodeURIComponent(this.o.handle!)}/keys`, { headers: { authorization: `Bearer ${this.credential}` } });
      if (listed.status !== 200) throw new Error(`the Owner Credential does not manage ${this.o.handle}: listing its keys answered ${listed.status}`);
      this.agent = await AgentClient.generate(this.o.handle!);
      const e = await this.agent.enroll(this.o.issuer, this.meta.agents_endpoint, this.credential);
      if (e.proof.status !== 200) throw new Error(`could not enroll a key for ${this.o.handle}: ${e.enroll.status}/${e.proof.status} ${e.proof.text.slice(0, 200)}`);
    } else {
      const owner = await this.newOwner('owner');
      this.ownerId = owner.owner_id;
      this.ownerEmail = owner.email;
      this.credential = owner.credential;
      this.agent = await this.newAgent(this.ownerId!, `scout-${slug()}`); // a fresh handle per run: the issuer may keep state between runs
    }
    if (this.o.adminToken) {
      this.client = await this.register({});
      this.cappedClient = await this.register({ max_signups_per_owner: 1 });
    } else {
      const f = this.o.client ?? { ...this.o.openClient!, clientSecret: '' };
      this.client = { client_id: f.clientId, client_secret: f.clientSecret, redirect_uri: f.redirectUri };
      // A fixture that cannot work would make every check fail, or pass for the wrong reason: prove it first with
      // one unmodified request and one complete sign-in, and blame the fixture, not the issuer, when they fail.
      const probe = await call(this.authUrl(this.client).url);
      if (probe.status !== 200 || obj(probe.json).status !== 'awaiting_agent') {
        throw new Error(`the client fixture does not work at this issuer: an unmodified Authentication Request answered ${probe.status} ${obj(probe.json).error ?? ''} ${obj(probe.json).error_description ?? ''}`.trim());
      }
      let exchanged: Res;
      try {
        exchanged = (await this.signIn()).tokenRes;
      } catch (e) {
        throw new Error(`the client fixture cannot complete a sign-in (check the redirect URI): ${(e as Error).message}`);
      }
      // The sign-in is complete only when the code was exchanged: a wrong secret shows here, and is the fixture's fault.
      if (exchanged.status !== 200 || typeof obj(exchanged.json).id_token !== 'string') {
        const error = obj(exchanged.json).error;
        throw new Error(`the client fixture cannot exchange a code${error === 'invalid_client' ? ' (the client secret is not accepted: invalid_client)' : ''}: the Token Endpoint answered ${exchanged.status} ${error ?? ''}`.trim());
      }
    }
    return true;
  }
  /** Leaves an existing Agent as it was found: revokes the keys this run enrolled and refuses the approvals it left waiting. */
  async cleanup(): Promise<void> {
    for (const id of this.awaitingOwner) {
      await call(`${this.o.issuer}/owner/transactions/${id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${this.credential}` }, json: { decision: 'refuse' } }).catch(() => undefined);
    }
    if (!this.o.handle || !this.meta) return;
    // Only the keys whose enrollment this run performed itself. A key that appeared on the Agent meanwhile, enrolled
    // by its Owner or by anything else, is not this run's to revoke.
    const base = `${this.meta.agents_endpoint}/${encodeURIComponent(this.o.handle)}/keys`;
    for (const kid of this.enrolledHere) {
      await call(`${base}/${encodeURIComponent(kid)}`, { method: 'DELETE', headers: { authorization: `Bearer ${this.o.ownerCredential}` } }).catch(() => undefined);
    }
  }

  // ---- checks ------------------------------------------------------------------------------------
  /** Runs every check inside this run's call context, so that each exchange, the Agent Client's included, is recorded. */
  run(): Promise<Report> {
    return callContext.run(this.cx, async () => {
      try {
        if (!await this.bootstrap()) return this.report();
        return await this.checks();
      } finally {
        await this.cleanup();
      }
    });
  }
  async checks(): Promise<Report> {
    const m = this.meta;
    const iss = this.o.issuer;

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
        if (redirect) expect(redirectMatches(redirect, this.client.redirect_uri) && redirect.searchParams.get('iss') === iss, `${name}: error redirect target`);
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
      for (const [k, v] of [['transaction_id', s.tx.transaction_id], ['challenge', s.tx.challenge], ['session_token', s.tx.session_token]] as const) expect(entropyBits(v) >= 128, `${k}: at most ${entropyBits(v)} bits`);
      const a = await this.assert(s.tx, this.agent, { accept_disclosure: true });
      const t = obj(a.json);
      expect(entropyBits(t.transaction_token) >= 128, `transaction_token: at most ${entropyBits(t.transaction_token)} bits`);
      const secret = typeof t.next?.url === 'string' ? new URL(t.next.url).pathname.split('/').pop() : undefined;
      expect(entropyBits(secret) >= 128, `continue URL secret: at most ${entropyBits(secret)} bits`);
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
    await this.check('I-12', 'login_hint: an assertion by another Agent is refused and changes nothing; the hinted Agent is accepted', async () => {
      const other = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const s = await this.start(this.client, { login_hint: this.agent.handle });
      expect(s.tx.login_hint === this.agent.handle, `the resource names the hint: ${s.tx.login_hint}`);
      const wrong = await this.assert(s.tx, other, { accept_disclosure: true });
      expect(wrong.status === 400 && obj(wrong.json).error === 'invalid_assertion' && obj(wrong.json).status === 'awaiting_agent', `another Agent → ${wrong.status} ${obj(wrong.json).error} ${obj(wrong.json).status}`);
      const still = obj((await this.get(s.tx)).json);
      expect(still.status === 'awaiting_agent' && still.challenge === s.tx.challenge, 'status or challenge changed');
      const right = await this.assert(s.tx, this.agent, { accept_disclosure: true });
      expect(right.status === 200 && obj(right.json).status === 'ready', `the hinted Agent → ${right.status} ${obj(right.json).status}`);
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
    await this.check('I-15', 'prompt=consent and require_review force the review even on a first visit with accept_disclosure', async () => {
      const first = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const forced = obj((await this.assert((await this.start(this.client, { prompt: 'consent' })).tx, first, { accept_disclosure: true })).json);
      expect(forced.status === 'awaiting_consent' && forced.next?.action === 'review', `first visit, prompt=consent, accept_disclosure → ${forced.status}`);
      expect(forced.consent_reason === 'prompt_consent' || forced.consent_reason === 'first_visit', `consent_reason ${forced.consent_reason}`);
      // The Agent declines: no Consent Record may exist afterwards, although the assertion carried accept_disclosure.
      const deny = await call(forced.next.url, { method: 'POST', headers: { authorization: `Bearer ${forced.transaction_token}` }, json: { decision: 'deny' } });
      expect(deny.status === 200 && obj(deny.json).status === 'denied' && obj(deny.json).reason === 'cancelled', `deny → ${deny.status} ${obj(deny.json).status}`);
      const plain = obj((await this.assert((await this.start()).tx, first)).json);
      expect(plain.status === 'awaiting_consent' && plain.consent_reason === 'first_visit', `after a declined forced review, a plain sign-in → ${plain.status} ${plain.consent_reason ?? ''}: a Consent Record was written before the review was decided`);

      const strict = await this.register({ require_review: true });
      const second = await this.newAgent(this.ownerId!);
      const policy = obj((await this.assert((await this.start(strict)).tx, second, { accept_disclosure: true })).json);
      expect(policy.status === 'awaiting_consent', `first visit, require_review, accept_disclosure → ${policy.status}`);
      const none = obj((await this.assert((await this.start(strict, { prompt: 'none' })).tx, second, { accept_disclosure: true })).json);
      expect(none.status === 'denied' && none.reason === 'consent_required', `require_review with prompt=none → ${none.status} ${none.reason}`);
      // once a Consent Record exists, the forced review is still due on every sign-in
      const allow = await call(policy.next.url, { method: 'POST', headers: { authorization: `Bearer ${policy.transaction_token}` }, json: { decision: 'allow' } });
      expect(allow.status === 200 && obj(allow.json).status === 'ready', `allow → ${allow.status}`);
      const again = obj((await this.assert((await this.start(strict)).tx, second, { accept_disclosure: true })).json);
      expect(again.status === 'awaiting_consent' && again.consent_reason === 'policy', `repeat sign-in at a require_review client → ${again.status} ${again.consent_reason}`);

      // Both gates at once (Section 6.6): the Owner's approval does not stand in for the review that is still due.
      const third = await this.newAgent(this.ownerId!);
      const both = obj((await this.assert((await this.start(this.client, { prompt: 'consent', scope: 'openid email owner_email' })).tx, third, { accept_disclosure: true })).json);
      expect(both.status === 'awaiting_owner', `Owner scope and a forced review → ${both.status}`);
      const approve = await call(`${iss}/owner/transactions/${both.transaction_id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${this.credential}` }, json: { decision: 'approve' } });
      expect(approve.status === 200 && obj(approve.json).status === 'awaiting_consent', `after the Owner approved → ${obj(approve.json).status}: the review was skipped`);
      this.awaitingOwner.delete(both.transaction_id);
      const reviewed = obj((await this.get(both, both.transaction_token)).json);
      expect(reviewed.status === 'awaiting_consent' && reviewed.next?.action === 'review', `resource after approval → ${reviewed.status}`);
      const done = await call(reviewed.next.url, { method: 'POST', headers: { authorization: `Bearer ${both.transaction_token}` }, json: { decision: 'allow' } });
      expect(obj(done.json).status === 'ready', `allow after approval → ${obj(done.json).status}`);
      const noneBoth = obj((await this.assert((await this.start(strict, { prompt: 'none', scope: 'openid email owner_email' })).tx, third, { accept_disclosure: true })).json);
      expect(noneBoth.status === 'denied' && noneBoth.reason === 'consent_required', `prompt=none with both gates outstanding → ${noneBoth.status} ${noneBoth.reason}`);
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
      expect(c.status === 200 && redirectMatches(r, this.client.redirect_uri) && r.searchParams.get('code') && r.searchParams.get('state') === s.params.state && r.searchParams.get('iss') === iss, `continue → ${c.status} ${c.text.slice(0, 160)}`);
      const twice = await this.cont(a.next.url, a.transaction_token);
      expect(twice.status === 410 && obj(twice.json).error === 'transaction_expired' && obj(twice.json).status === 'completed', `second continue → ${twice.status}`);
      // deliver_to_session path, HTML redirect
      const s2 = await this.start();
      const a2 = obj((await this.assert(s2.tx, this.agent, { accept_disclosure: true, deliver_to_session: true })).json);
      const sess = obj((await this.get(s2.tx, s2.tx.session_token)).json);
      expect(typeof sess.next?.url === 'string', 'continue URL released to the Session Holder with deliver_to_session');
      const html = await call(sess.next.url, { headers: { accept: 'text/html', authorization: `Bearer ${s2.tx.session_token}` } });
      expect(html.status === 303 && redirectMatches(new URL(html.headers.get('location') ?? 'https://invalid.example/'), this.client.redirect_uri) && (html.headers.get('cache-control') ?? '').includes('no-store'), `html continue → ${html.status} ${html.headers.get('cache-control')}`);
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
    const concurrentlyIssuedTokens: string[] = [];
    await this.check('I-19', 'A fresh code succeeds sequentially; concurrent Token Requests redeem at most once', async () => {
      const sequential = await this.signIn();
      expect(sequential.tokenRes.status === 200 && typeof sequential.token.access_token === 'string' && typeof sequential.token.id_token === 'string', `sequential redemption → ${sequential.tokenRes.status}`);
      for (let round = 0; round < 3; round += 1) {
        const { code, verifier } = await this.codeFor();
        const results = await Promise.all(Array.from({ length: 6 }, () => this.exchange(this.client, code, verifier)));
        concurrentlyIssuedTokens.push(...concurrentAccessTokens(results));
      }
    });
    await this.check('I-19', 'Replay invalidates any token returned during concurrent redemption (SHOULD, Section 5.4)', async () => {
      if (concurrentlyIssuedTokens.length === 0) throw new Skip('no token was returned before replay invalidated the concurrent redemptions; there is no issued token to test');
      let stillUsable = 0;
      for (const token of concurrentlyIssuedTokens) {
        const ui = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${token}` } });
        if (ui.status === 200) stillUsable += 1;
        else expect(ui.status === 401 && obj(ui.json).error === 'invalid_token', `UserInfo after replay → ${ui.status} ${obj(ui.json).error ?? ''}`);
      }
      if (stillUsable) throw new Skip(`${stillUsable} token(s) remain usable after replay: the Section 5.4 revocation recommendation (SHOULD) was not followed`);
    });
    await this.check('I-19', 'A Registered Client must authenticate: a wrong secret or none answers 401 invalid_client and no tokens', async () => {
      if (!this.client.client_secret) throw new Skip('needs a Registered Client');
      const form = (code: string, verifier: string) => ({ grant_type: 'authorization_code', code, redirect_uri: this.client.redirect_uri, code_verifier: verifier });
      const a = await this.codeFor();
      const wrong = await this.exchange({ ...this.client, client_secret: `${this.client.client_secret}x` }, a.code, a.verifier);
      expect(wrong.status === 401 && obj(wrong.json).error === 'invalid_client' && obj(wrong.json).access_token === undefined, `wrong secret → ${wrong.status} ${obj(wrong.json).error}`);
      const b = await this.codeFor();
      const none = await call(m.token_endpoint, { method: 'POST', form: { client_id: this.client.client_id, ...form(b.code, b.verifier) } });
      expect(none.status === 401 && obj(none.json).error === 'invalid_client' && obj(none.json).access_token === undefined, `no client authentication → ${none.status} ${obj(none.json).error}`);
      const c = await this.codeFor();
      const good = await this.exchange(this.client, c.code, c.verifier);
      expect(good.status === 200, `the right secret → ${good.status}`);
    });
    await this.check('I-19', 'Open Client: PKCE, redirect_uri and client_id are verified at the Token Endpoint', async () => {
      if (!this.o.openClient) throw new Skip('no openClient configured');
      const oc: RegisteredClient = { client_id: this.o.openClient.clientId, client_secret: '', redirect_uri: this.o.openClient.redirectUri };
      const post = (form: Record<string, string>) => call(m.token_endpoint, { method: 'POST', form: { grant_type: 'authorization_code', ...form } });
      const refused = async (name: string, mutate: (f: Record<string, string>) => Record<string, string>) => {
        const { code, verifier } = await this.codeFor(oc); // a fresh code per case: an issuer may void a code after a failed attempt
        const r = await post(mutate({ client_id: oc.client_id, code, redirect_uri: oc.redirect_uri, code_verifier: verifier }));
        expect(r.status === 400 && obj(r.json).error === 'invalid_grant' && obj(r.json).access_token === undefined, `${name} → ${r.status} ${obj(r.json).error}`);
      };
      await refused('a wrong code_verifier', (f) => ({ ...f, code_verifier: rnd(32) }));
      await refused('no code_verifier', ({ code_verifier: _v, ...f }) => f);
      await refused('another redirect_uri', (f) => ({ ...f, redirect_uri: `${f.redirect_uri}x` }));
      const { code, verifier } = await this.codeFor(oc);
      const other = await post({ client_id: this.client.client_id === oc.client_id ? `${oc.client_id}x` : this.client.client_id, code, redirect_uri: oc.redirect_uri, code_verifier: verifier });
      expect(other.status >= 400 && obj(other.json).access_token === undefined, `another client_id → ${other.status}`);
      const ok = await this.codeFor(oc);
      const good = await post({ client_id: oc.client_id, code: ok.code, redirect_uri: oc.redirect_uri, code_verifier: ok.verifier });
      expect(good.status === 200 && typeof obj(good.json).id_token === 'string', `the correct request → ${good.status} ${good.text.slice(0, 120)}`);
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
      const wrongClient = await this.exchange(this.capped(), c3.searchParams.get('code')!, s3.verifier);
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
      expect(payload.owner_email !== undefined && payload.owner_email_verified === true && ['email', 'oidc', 'domain', 'passkey'].includes(payload.owner_verified_via as string), `owner claims ${JSON.stringify(payload).slice(0, 200)}`);
      expect(typeof payload.owner_name === 'string' && payload.owner_name.length > 0, 'owner_profile was granted but owner_name is missing');
    });
    await this.check('I-22', 'A requested Owner Claim the issuer cannot supply ends the sign-in; the token never omits it', async () => {
      // An Owner without a display name: `owner_profile` cannot be satisfied (Section 6.6).
      const nameless = await this.admin('/admin/owners', { email: `nameless-${slug()}@example.com`, verified_via: 'passkey', session_auth: 'passkey' });
      const saved = this.credential;
      this.credential = nameless.credential;
      try {
        for (const shareOwner of [true, false]) {
          const agent = await this.newAgent(nameless.owner_id);
          if (shareOwner) {
            const grant = await call(`${m.agents_endpoint}/${encodeURIComponent(agent.handle)}/keys/${encodeURIComponent(agent.kid)}`, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { permissions: { share_owner: true } } });
            expect(grant.status === 200, `share_owner grant → ${grant.status}`);
          }
          const which = shareOwner ? 'key with share_owner' : 'key without share_owner';
          const s = await this.start(this.client, { scope: 'openid email owner_profile' });
          const a = obj((await this.assert(s.tx, agent, { accept_disclosure: true })).json);
          if (a.status === 'denied') {
            expect(a.reason === 'access_denied', `${which}: denied with ${a.reason}`);
            continue;
          }
          // Whatever path the issuer takes instead, it must not end in a token without the claim: follow it to the end.
          const end = await this.driveToEnd(a, a.transaction_token, this.credential);
          if (end.status !== 'ready') {
            expect(end.status === 'denied', `${which}: the transaction ended ${end.status}`);
            continue;
          }
          const c = await this.cont(end.next.url, a.transaction_token);
          const t = await this.exchange(this.client, new URL(obj(c.json).redirect).searchParams.get('code')!, s.verifier);
          if (t.status !== 200) continue; // refused at the Token Endpoint: no token either
          const { payload } = await jwtVerify(obj(t.json).id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss });
          expect(typeof payload.owner_name === 'string' && payload.owner_name.length > 0, `${which}: a token was issued for owner_profile without owner_name`);
        }
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-23', 'UserInfo returns 401 invalid_token after key revocation; sub matches; accepted nowhere else', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const r = await this.signIn(this.client, fresh);
      const ui = await call(m.userinfo_endpoint, { headers: { authorization: `Bearer ${r.token.access_token}` } });
      const { payload } = await jwtVerify(r.token.id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss });
      expect(ui.status === 200 && obj(ui.json).sub === payload.sub && obj(ui.json).email === fresh.handle, `userinfo ${ui.status} ${ui.text.slice(0, 160)}`);
      // Accepted nowhere else (Section 5.6): not as a management credential, not on a transaction, not at a continue URL.
      const at = { authorization: `Bearer ${r.token.access_token}` };
      const asManager = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys`, { headers: at });
      expect(asManager.status === 401, `Access Token at the agents endpoint → ${asManager.status}`);
      const open = await this.start();
      const ready = obj((await this.assert(open.tx, fresh)).json);
      expect(ready.status === 'ready', `second sign-in → ${ready.status}`);
      const onTx = await call(open.tx.url, { headers: at });
      expect(onTx.status === 401 && obj(onTx.json).error === 'invalid_token', `Access Token on a Transaction Resource → ${onTx.status}`);
      const onContinue = await call(ready.next.url, { headers: at });
      expect(onContinue.status === 401, `Access Token at a continue URL → ${onContinue.status}`);
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
      const other = obj((await this.assert((await this.start(this.capped())).tx, fresh, { accept_disclosure: true })).json);
      expect(other.status === 'ready', 'other client unaffected');
      const en = await call(acct, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'enabled' } });
      expect(en.status === 200 && obj(en.json).sign_in_count === 1 && obj(en.json).status === 'enabled', `re-enable → ${en.text.slice(0, 160)}`);
      const list = await call(`${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/accounts`, { headers: { authorization: `Bearer ${this.credential}` } });
      expect(list.status === 200 && Array.isArray(obj(list.json).accounts), 'list accounts');
      // a code issued before the Account was disabled is void afterwards (Section 7.4 table)
      const pending = await this.codeFor(this.client, fresh);
      const off = await call(acct, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'disabled' } });
      expect(off.status === 200, `disable → ${off.status}`);
      const late = await this.exchange(this.client, pending.code, pending.verifier);
      expect(late.status === 400 && obj(late.json).error === 'invalid_grant', `unredeemed code after the Account was disabled → ${late.status} ${obj(late.json).error}`);
    });
    await this.check('I-28', 'Agents asserting at once cannot take more places than the cap allows', async () => {
      if (!this.o.adminToken) throw new Skip('needs adminToken');
      const saved = this.credential;
      try {
        for (let round = 0; round < 3; round += 1) { // a fresh Owner and client each round: a race shows only sometimes
          const owner = await this.newOwner('race');
          this.credential = owner.credential;
          const one = await this.register({ max_signups_per_owner: 1 });
          const started = [];
          for (let i = 0; i < 8; i += 1) started.push({ a: await this.newAgent(owner.owner_id), tx: (await this.start(one)).tx });
          const signed = await Promise.all(started.map(async ({ a, tx }) => ({ url: tx.next.url as string, assertion: await a.assertion(this.o.issuer, tx as never, { accept_disclosure: true }) })));
          const results = (await Promise.all(signed.map((x) => call(x.url, { method: 'POST', json: { assertion: x.assertion } })))).map((r) => obj(r.json));
          const admitted = results.filter((r) => r.status === 'ready').length;
          const refused = results.filter((r) => r.status === 'denied' && r.reason === 'signup_limit_reached').length;
          expect(admitted === 1 && refused === started.length - 1, `round ${round}: cap 1, eight Agents at once → ${admitted} admitted, ${refused} refused`);
        }
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-28', 'The cap counts Agents and Accounts as Section 7.6 says: open transactions of an Agent with an Account, deleted Agents, denied transactions', async () => {
      if (!this.o.adminToken) throw new Skip('needs adminToken');
      const owner = await this.newOwner('count');
      const saved = this.credential;
      this.credential = owner.credential;
      try {
        // An Agent with an Account and another transaction still open holds one place, not two.
        const two = await this.register({ max_signups_per_owner: 2 });
        const a = await this.newAgent(owner.owner_id);
        const b = await this.newAgent(owner.owner_id);
        const t1 = obj((await this.assert((await this.start(two)).tx, a, { accept_disclosure: true })).json);
        const t2 = obj((await this.assert((await this.start(two)).tx, a, { accept_disclosure: true })).json);
        expect(t1.status === 'ready' && t2.status === 'ready', `two transactions of one Agent → ${t1.status}, ${t2.status}`);
        expect((await this.cont(t1.next.url, t1.transaction_token)).status === 200, 'the first completes');
        const second = obj((await this.assert((await this.start(two)).tx, b, { accept_disclosure: true })).json);
        expect(second.status === 'ready', `cap 2, one Account and that Agent's other open transaction: the Owner's second Agent → ${second.status} ${second.reason ?? ''}`);

        // The Account of a deleted Agent still counts.
        const one = await this.register({ max_signups_per_owner: 1 });
        const gone = await this.newAgent(owner.owner_id);
        const code = await this.codeFor(one, gone);
        expect((await this.exchange(one, code.code, code.verifier)).status === 200, 'first Agent signs in');
        await this.admin(`/admin/agents/${encodeURIComponent(gone.handle)}`, undefined, 'DELETE');
        const next = obj((await this.assert((await this.start(one)).tx, b, { accept_disclosure: true })).json);
        expect(next.status === 'denied' && next.reason === 'signup_limit_reached', `after the only Agent with an Account was deleted, the next Agent → ${next.status} ${next.reason ?? ''}`);

        // A transaction that ended denied holds no place.
        const strict = await this.register({ max_signups_per_owner: 1, require_review: true });
        const c = await this.newAgent(owner.owner_id);
        const d = await this.newAgent(owner.owner_id);
        const waiting = obj((await this.assert((await this.start(strict)).tx, c, { accept_disclosure: true })).json);
        expect(waiting.status === 'awaiting_consent', `require_review → ${waiting.status}`);
        const blocked = obj((await this.assert((await this.start(strict)).tx, d, { accept_disclosure: true })).json);
        expect(blocked.status === 'denied' && blocked.reason === 'signup_limit_reached', `while the first is in flight → ${blocked.status} ${blocked.reason ?? ''}`);
        const declined = await call(waiting.next.url, { method: 'POST', headers: { authorization: `Bearer ${waiting.transaction_token}` }, json: { decision: 'deny' } });
        expect(obj(declined.json).status === 'denied', `deny → ${obj(declined.json).status}`);
        const freed = obj((await this.assert((await this.start(strict)).tx, d, { accept_disclosure: true })).json);
        expect(freed.status === 'awaiting_consent', `after the first was denied → ${freed.status} ${freed.reason ?? ''}`);
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-28', 'Concurrent first completions of one Agent count once toward the cap', async () => {
      if (!this.o.adminToken) throw new Skip('needs adminToken');
      const owner = await this.newOwner('twice');
      const saved = this.credential;
      this.credential = owner.credential;
      try {
        const two = await this.register({ max_signups_per_owner: 2 });
        const a1 = await this.newAgent(owner.owner_id);
        const a2 = await this.newAgent(owner.owner_id);
        const a3 = await this.newAgent(owner.owner_id);
        const txs = [];
        for (let i = 0; i < 3; i += 1) txs.push(obj((await this.assert((await this.start(two)).tx, a1, { accept_disclosure: true })).json));
        expect(txs.every((t) => t.status === 'ready'), `one Agent, three transactions → ${txs.map((t) => `${t.status} ${t.reason ?? ''}`).join(', ')}`);
        const done = await Promise.all(txs.map((t) => this.cont(t.next.url, t.transaction_token)));
        expect(done.every((d) => d.status === 200), 'all three complete');
        const second = obj((await this.assert((await this.start(two)).tx, a2, { accept_disclosure: true })).json);
        expect(second.status === 'ready', `the Owner's second Agent under a cap of two → ${second.status} ${second.reason ?? ''}`);
        expect((await this.cont(second.next.url, second.transaction_token)).status === 200, 'second Agent completes');
        const third = obj((await this.assert((await this.start(two)).tx, a3, { accept_disclosure: true })).json);
        expect(third.status === 'denied' && third.reason === 'signup_limit_reached', `the third Agent → ${third.status} ${third.reason ?? ''}`);
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-28', 'Per-owner cap counts Accounts ever created plus in-flight transactions; signup_limit_reached', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const owner = await this.newOwner('capped');
      const saved = this.credential;
      this.credential = owner.credential;
      try {
        const a1 = await this.newAgent(owner.owner_id);
        const a2 = await this.newAgent(owner.owner_id);
        const inflight = await this.start(this.capped());
        const i = obj((await this.assert(inflight.tx, a1, { accept_disclosure: true })).json);
        expect(i.status === 'ready', 'first agent passes the cap');
        const second = obj((await this.assert((await this.start(this.capped())).tx, a2, { accept_disclosure: true })).json);
        expect(second.status === 'denied' && second.reason === 'signup_limit_reached', `second agent while first in flight → ${second.status} ${second.reason}`);
        const c = await this.cont(i.next.url, i.transaction_token);
        expect(new URL(obj((await this.cont(second.next.url, second.transaction_token)).json).redirect).searchParams.get('error') === 'signup_limit_reached', 'redirect error');
        expect(c.status === 200, 'first completes');
        const again = obj((await this.assert((await this.start(this.capped())).tx, a1)).json);
        expect(again.status === 'ready', `existing account signs in regardless of the cap: ${again.status}`);
        const dis = await call(`${m.agents_endpoint}/${encodeURIComponent(a1.handle)}/accounts/${encodeURIComponent(this.capped().client_id)}`, { method: 'PATCH', headers: { authorization: `Bearer ${this.credential}` }, json: { status: 'disabled' } });
        expect(dis.status === 200, 'disable');
        const still = obj((await this.assert((await this.start(this.capped())).tx, a2, { accept_disclosure: true })).json);
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
    await this.check('I-38', 'Authentication Request by GET and POST; request, request_uri, response_mode and response_type refused on the JSON, HTML and POST paths; state and nonce never rejected on length', async () => {
      expect(m.request_parameter_supported === false && m.request_uri_parameter_supported === false, `request_parameter_supported ${m.request_parameter_supported}, request_uri_parameter_supported ${m.request_uri_parameter_supported}`);
      const form = (url: string) => Object.fromEntries(new URL(url).searchParams);
      const post = await call(m.authorization_endpoint, { method: 'POST', form: form(this.authUrl(this.client).url) });
      const pt = obj(post.json);
      expect(post.status === 200 && pt.status === 'awaiting_agent' && typeof pt.session_token === 'string' && typeof pt.challenge === 'string', `POST form body → ${post.status} ${post.text.slice(0, 160)}`);
      const cases: Array<[string, Record<string, string>, string]> = [
        ['request', { request: 'eyJhbGciOiJub25lIn0.e30.' }, 'request_not_supported'],
        ['request_uri', { request_uri: 'https://rp.example/request.jwt' }, 'request_uri_not_supported'],
        ...['fragment', 'form_post', 'jwt', 'query.jwt', 'web_message'].map((v): [string, Record<string, string>, string] => [`response_mode=${v}`, { response_mode: v }, 'invalid_request']),
        ...['token', 'id_token', 'none', 'code id_token', 'code token', 'Code'].map((v): [string, Record<string, string>, string] => [`response_type=${v}`, { response_type: v }, 'unsupported_response_type']),
      ];
      /** The error redirect of Section 5.2: to the registered redirect_uri, with error, the request's state and iss. */
      const errorAt = (name: string, target: unknown, error: string, state: string | undefined) => {
        expect(typeof target === 'string' && target.length > 0, `${name}: no redirect URL`);
        const l = new URL(target);
        expect(redirectMatches(l, this.client.redirect_uri) && l.searchParams.get('error') === error && l.searchParams.get('state') === state && l.searchParams.get('iss') === iss, `${name}: error redirect ${target}`);
      };
      for (const [name, over, error] of cases) {
        const u = this.authUrl(this.client, over);
        for (const [path, r] of [['GET, JSON', await call(u.url)], ['POST, JSON', await call(m.authorization_endpoint, { method: 'POST', form: form(u.url) })]] as Array<[string, Res]>) {
          const j = obj(r.json);
          expect(r.status === 400 && j.error === error, `${name} (${path}): ${r.status} ${j.error ?? r.text.slice(0, 120)}`);
          errorAt(`${name} (${path})`, j.redirect, error, u.params.state);
        }
        // The path a Relying Party's browser redirect takes.
        const h = await call(u.url, { headers: { accept: 'text/html' } });
        expect(h.status === 303, `${name} (GET, HTML): ${h.status} ${h.text.slice(0, 120)}`);
        errorAt(`${name} (GET, HTML)`, h.headers.get('location'), error, u.params.state);
      }
      // Section 3.1 of RFC 6749 treats a parameter sent without a value as omitted, so an empty response_mode is either accepted as absent or refused like any other value.
      const empty = await call(this.authUrl(this.client, { response_mode: '' }).url);
      expect((empty.status === 200 && obj(empty.json).status === 'awaiting_agent') || (empty.status === 400 && obj(empty.json).error === 'invalid_request'), `response_mode without a value: ${empty.status} ${obj(empty.json).error ?? obj(empty.json).status ?? ''}`);
      const query = await this.start(this.client, { response_mode: 'query' });
      expect(query.tx.status === 'awaiting_agent', 'response_mode=query accepted');
      const short = await this.start(this.client, { state: 's', nonce: 'n' });
      expect(short.tx.status === 'awaiting_agent', 'one-character state and nonce accepted');
      // 512 characters each: accepted on both paths and returned unchanged (Sections 5.4, 3.1).
      const long = { state: rnd(384), nonce: rnd(384) };
      const ls = await call(this.authUrl(this.client, long).url);
      expect(ls.status === 200 && obj(ls.json).status === 'awaiting_agent', `512-character state and nonce (JSON) → ${ls.status} ${obj(ls.json).error ?? ''}`);
      const lh = await call(this.authUrl(this.client, long).url, { headers: { accept: 'text/html' } });
      expect(lh.status === 303 && !new URL(lh.headers.get('location') ?? 'http://invalid/?error=none').searchParams.has('error'), `512-character state and nonce (HTML) → ${lh.status} ${lh.headers.get('location') ?? ''}`);
      const lp = this.authUrl(this.client, long);
      const lt = obj((await call(lp.url)).json);
      const la = obj((await this.assert(lt, this.agent, { accept_disclosure: true })).json);
      expect(la.status === 'ready', `sign-in with a 512-character state and nonce → ${la.status} ${la.reason ?? ''}`);
      const lr = new URL(obj((await this.cont(la.next.url, la.transaction_token)).json).redirect);
      expect(lr.searchParams.get('state') === long.state, 'a 512-character state must come back unchanged on the redirect');
      const tok = await this.exchange(this.client, lr.searchParams.get('code')!, lp.verifier);
      expect(tok.status === 200, `exchange → ${tok.status} ${obj(tok.json).error ?? ''}`);
      const { payload } = await jwtVerify(obj(tok.json).id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss, audience: this.client.client_id });
      expect(payload.nonce === long.nonce, 'a 512-character nonce must come back unchanged in the ID Token');
    });
    await this.check('I-39', 'Step 3/4 failure after a valid client: HTML 303 to redirect_uri with error, state, iss; JSON 400 with redirect; step 1 failure answers 400 directly', async () => {
      const a = this.authUrl(this.client, { nonce: undefined });
      const h = await call(a.url, { headers: { accept: 'text/html' } });
      const loc = h.headers.get('location');
      expect(h.status === 303 && !!loc, `HTML step 3 failure → ${h.status} ${loc ?? h.text.slice(0, 120)}`);
      const l = new URL(loc!);
      expect(redirectMatches(l, this.client.redirect_uri) && l.searchParams.get('error') === 'invalid_request' && l.searchParams.get('state') === a.params.state && l.searchParams.get('iss') === iss, `HTML error redirect ${loc}`);
      expect((h.headers.get('cache-control') ?? '').includes('no-store'), 'no-store on the error redirect');
      const scope = this.authUrl(this.client, { scope: 'email profile' });
      const j = await call(scope.url);
      const jb = obj(j.json);
      expect(j.status === 400 && jb.error === 'invalid_scope' && typeof jb.redirect === 'string', `JSON step 4 failure → ${j.status} ${j.text.slice(0, 160)}`);
      const r = new URL(jb.redirect);
      expect(redirectMatches(r, this.client.redirect_uri) && r.searchParams.get('error') === 'invalid_scope' && r.searchParams.get('state') === scope.params.state && r.searchParams.get('iss') === iss, `JSON redirect member ${jb.redirect}`);
      const h4 = await call(scope.url, { headers: { accept: 'text/html' } });
      expect(h4.status === 303 && new URL(h4.headers.get('location') ?? 'http://invalid/').searchParams.get('error') === 'invalid_scope', `HTML step 4 failure → ${h4.status} ${h4.headers.get('location') ?? ''}`);
      const unknown = this.authUrl({ ...this.client, client_id: `unknown-${rnd(4)}` });
      const uj = await call(unknown.url);
      expect(uj.status === 400 && obj(uj.json).error === 'invalid_request' && obj(uj.json).redirect === undefined && !uj.headers.get('location'), `JSON step 1 failure → ${uj.status} ${uj.text.slice(0, 120)}`);
      const uh = await call(unknown.url, { headers: { accept: 'text/html' } });
      expect(uh.status === 400 && !uh.headers.get('location') && (uh.headers.get('content-type') ?? '').includes('text/html'), `HTML step 1 failure → ${uh.status} ${uh.headers.get('content-type')} ${uh.headers.get('location') ?? ''}`);
      // Step 1 also fails when the Client ID Metadata Document is one the Issuer must refuse (Sections 3.2, 4.2): invalid_request, whatever is wrong with it.
      for (const oc of this.o.invalidOpenClients ?? []) {
        const bad = this.authUrl({ client_id: oc.clientId, client_secret: '', redirect_uri: oc.redirectUri });
        const bj = await call(bad.url);
        expect(bj.status === 400 && obj(bj.json).error === 'invalid_request' && obj(bj.json).redirect === undefined && !bj.headers.get('location'), `Open Client document the Issuer must refuse (${oc.name}), JSON path → ${bj.status} ${bj.text.slice(0, 160)}`);
        const bh = await call(bad.url, { headers: { accept: 'text/html' } });
        expect(bh.status === 400 && !bh.headers.get('location') && (bh.headers.get('content-type') ?? '').includes('text/html'), `Open Client document the Issuer must refuse (${oc.name}), HTML path → ${bh.status} ${bh.headers.get('content-type')} ${bh.headers.get('location') ?? ''}`);
      }
    });
    await this.check('I-40', 'Loopback IP literal redirect_uri of a Registered Client matches with any port and nothing else differing; everything else by simple string comparison', async () => {
      const exact = `https://rp-${slug()}.example/cb`;
      const reg = await this.register({ redirect_uris: ['http://127.0.0.1:8080/cb', 'http://[::1]:8080/cb', 'http://localhost:8080/cb', exact] });
      const at = (redirect_uri: string): RegisteredClient => ({ ...reg, redirect_uri });
      const v4 = await this.start(at('http://127.0.0.1:49152/cb'));
      expect(v4.tx.client?.redirect_host === '127.0.0.1:49152', `IPv4 loopback with another port: redirect_host ${v4.tx.client?.redirect_host}`);
      const v6 = await this.start(at('http://[::1]:49153/cb'));
      expect(v6.tx.status === 'awaiting_agent', 'IPv6 loopback with another port');
      const same = await this.start(at(exact));
      expect(same.tx.status === 'awaiting_agent', 'exact https redirect_uri');
      // Only the port may differ. Each of these is another string that a URL parser would equate with a registered value or with its host.
      const rejected: Array<[string, string]> = [
        ['loopback with another path', 'http://127.0.0.1:8080/cb/'],
        ['loopback with a query', 'http://127.0.0.1:8080/cb?x=1'],
        ['loopback with an empty query', 'http://127.0.0.1:49152/cb?'],
        ['loopback with a fragment', 'http://127.0.0.1:49152/cb#frag'],
        ['loopback with userinfo', 'http://user:pw@127.0.0.1:49152/cb'],
        ['loopback written 127.1', 'http://127.1:49152/cb'],
        ['loopback written as an integer', 'http://2130706433:49152/cb'],
        ['loopback written in hexadecimal', 'http://0x7f.0.0.1:49152/cb'],
        ['loopback with a .. segment', 'http://127.0.0.1:49152/x/../cb'],
        ['loopback with a . segment', 'http://127.0.0.1:49152/./cb'],
        ['loopback with an upper-case scheme', 'HTTP://127.0.0.1:49152/cb'],
        ['another loopback address', 'http://127.0.0.2:8080/cb'],
        ['IPv6 loopback written in full', 'http://[0:0:0:0:0:0:0:1]:49153/cb'],
        ['localhost with another port', 'http://localhost:9090/cb'],
        ['https on the loopback host', 'https://127.0.0.1:8080/cb'],
        ['trailing slash', `${exact}/`],
        ['upper-case path', exact.replace('/cb', '/CB')],
        ['explicit default port', exact.replace('.example/', '.example:443/')],
        ['upper-case scheme', exact.replace('https://', 'HTTPS://')],
      ];
      for (const [name, uri] of rejected) {
        const r = await call(this.authUrl(at(uri)).url);
        expect(r.status === 400 && obj(r.json).error === 'invalid_request' && obj(r.json).redirect === undefined && !r.headers.get('location'), `${name} (${uri}): ${r.status} ${r.text.slice(0, 120)}`);
        const h = await call(this.authUrl(at(uri)).url, { headers: { accept: 'text/html' } });
        expect(h.status === 400 && !h.headers.get('location'), `${name} (${uri}), HTML path: ${h.status} ${h.headers.get('location') ?? ''}`);
      }
      if (this.o.openClient) {
        const u = new URL(this.o.openClient.redirectUri);
        if (u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === '[::1]')) {
          u.port = String(Number(u.port || 80) + 1);
          const r = await call(this.authUrl({ client_id: this.o.openClient.clientId, client_secret: '', redirect_uri: u.href }).url);
          expect(r.status === 400 && obj(r.json).redirect === undefined, `Open Client loopback with another port must not match: ${r.status}`);
        }
      }
    });
    await this.check('I-41', 'Concurrent assertions: exactly one accepted, the other assertion_replayed; concurrent ready continues: exactly one code', async () => {
      const second = await AgentClient.generate(this.agent.handle);
      const e = await second.enroll(iss, m.agents_endpoint, this.credential);
      expect(e.proof.status === 200, `second key for the handle → ${e.enroll.status}/${e.proof.status}`);
      const s = await this.start();
      const [r1, r2] = await Promise.all([this.assert(s.tx, this.agent, { accept_disclosure: true }), this.assert(s.tx, second, { accept_disclosure: true })]);
      const accepted = [r1, r2].filter((r) => r.status === 200);
      const replayed = [r1, r2].filter((r) => r.status === 409 && obj(r.json).error === 'assertion_replayed');
      expect(accepted.length === 1 && replayed.length === 1, `concurrent assertions → ${r1.status} ${obj(r1.json).error ?? obj(r1.json).status} / ${r2.status} ${obj(r2.json).error ?? obj(r2.json).status}`);
      const t = obj(accepted[0]!.json);
      expect(t.status === 'ready' && typeof t.transaction_token === 'string' && typeof t.next?.url === 'string', `accepted assertion → ${t.status}`);
      expect(obj(replayed[0]!.json).transaction_token === undefined && obj(replayed[0]!.json).status === 'ready', 'the replayed assertion gets no transaction_token and sees the new status');
      const [c1, c2] = await Promise.all([this.cont(t.next.url, t.transaction_token), this.cont(t.next.url, t.transaction_token)]);
      const codes = [c1, c2].filter((c) => c.status === 200 && typeof obj(c.json).redirect === 'string' && new URL(obj(c.json).redirect).searchParams.has('code'));
      const gone = [c1, c2].filter((c) => c.status === 410 && obj(c.json).error === 'transaction_expired');
      expect(codes.length === 1 && gone.length === 1, `concurrent continues → ${c1.status} ${obj(c1.json).error ?? ''} / ${c2.status} ${obj(c2.json).error ?? ''}`);
      const token = await this.exchange(this.client, new URL(obj(codes[0]!.json).redirect).searchParams.get('code')!, s.verifier);
      expect(token.status === 200, `the single code exchanges → ${token.status} ${token.text.slice(0, 120)}`);
    });
    await this.check('I-42', 'typ application/agent-login+jwt and case variants accepted as agent-login+jwt; same for the enrollment type', async () => {
      for (const typ of ['application/agent-login+jwt', 'Agent-Login+JWT', 'APPLICATION/AGENT-LOGIN+JWT']) {
        const s = await this.start();
        const r = await this.assert(s.tx, this.agent, { accept_disclosure: true }, { header: { typ } });
        expect(r.status === 200 && obj(r.json).status === 'ready', `assertion typ ${typ} → ${r.status} ${r.text.slice(0, 120)}`);
      }
      const base = `${m.agents_endpoint}/${encodeURIComponent(this.agent.handle)}/keys`;
      const prove = async (typ: string) => {
        const k = await AgentClient.generate(this.agent.handle);
        const en = await call(base, { method: 'POST', headers: { authorization: `Bearer ${this.credential}` }, json: { jwk: k.publicJwk, name: `typ ${typ}` } });
        expect(en.status === 201, `enroll → ${en.status} ${en.text.slice(0, 120)}`);
        const proof = await k.assertion(iss, { transaction_id: 'x', challenge: obj(en.json).challenge }, {}, { header: { typ }, payload: { txn: undefined } });
        return call(obj(en.json).proof_url, { method: 'POST', json: { proof } });
      };
      for (const typ of ['application/agent-login-enrollment+jwt', 'Agent-Login-Enrollment+JWT', 'APPLICATION/AGENT-LOGIN-ENROLLMENT+JWT']) {
        const r = await prove(typ);
        expect(r.status === 200 && obj(r.json).status === 'active', `enrollment typ ${typ} → ${r.status} ${r.text.slice(0, 120)}`);
      }
      const wrong = await prove('application/jwt');
      expect(wrong.status === 400 && obj(wrong.json).error === 'invalid_assertion', `enrollment typ application/jwt → ${wrong.status} ${obj(wrong.json).error}`);
      const swapped = await prove('agent-login+jwt');
      expect(swapped.status === 400 && obj(swapped.json).error === 'invalid_assertion', `assertion typ on an enrollment proof → ${swapped.status} ${obj(swapped.json).error}`);
    });
    await this.check('I-43', 'Bodies of an existing transaction carry next.url for continue only for the credential that releases it (ready and denied); error precedence invalid_transaction, invalid_token, transaction_expired, then any other', async () => {
      interface T { tx: Record<string, any>; assertUrl: string; reviewUrl: string; token: string; session: string; continueUrl: string; status: string }
      const auth = (t?: string): Record<string, string> => (t ? { authorization: `Bearer ${t}` } : {});
      /** A transaction taken through the review step, which makes its assertion and review URLs known; `allow` leaves it ready, `deny` denied. */
      const through = async (decision: 'allow' | 'deny', deliver: boolean): Promise<T> => {
        const s = await this.start(this.client, { prompt: 'consent' });
        const a = obj((await this.assert(s.tx, this.agent, deliver ? { deliver_to_session: true } : {})).json);
        expect(a.status === 'awaiting_consent' && typeof a.next?.url === 'string' && typeof a.transaction_token === 'string', `prompt=consent → ${a.status} ${a.reason ?? ''}`);
        const d = await call(a.next.url, { method: 'POST', headers: auth(a.transaction_token), json: { decision } });
        const t = obj(d.json);
        expect(d.status === 200 && t.status === (decision === 'allow' ? 'ready' : 'denied') && typeof t.next?.url === 'string', `${decision} → ${d.status} ${t.status ?? t.error}`);
        return { tx: s.tx, assertUrl: s.tx.next.url, reviewUrl: a.next.url, token: a.transaction_token, session: s.tx.session_token, continueUrl: t.next.url, status: t.status };
      };
      /** One request and what its answer must be: HTTP status, error (none for a 200), the transaction's status, and next.url released or withheld. */
      const says = async (name: string, request: Promise<Res>, status: number, error: string | undefined, t: T, released: boolean) => {
        const r = await request;
        const j = obj(r.json);
        expect(r.status === status && j.error === error, `${name} → ${r.status} ${j.error ?? ''}, expected ${status} ${error ?? ''}`);
        expect(j.status === t.status && j.next?.action === 'continue', `${name}: the body must carry status ${t.status} and next continue, has ${j.status} and ${j.next?.action}`);
        expect(released ? j.next.url === t.continueUrl : j.next.url === undefined, `${name}: next.url must be ${released ? 'released to' : 'withheld from'} this requester`);
      };
      const replay = async (t: T, bearer?: string) => call(t.assertUrl, { method: 'POST', headers: auth(bearer), json: { assertion: await this.agent.assertion(iss, t.tx as never) } });
      const decide = (t: T, bearer?: string, body: unknown = { decision: 'allow' }) => call(t.reviewUrl, { method: 'POST', headers: auth(bearer), json: body });
      const read = (t: T, bearer?: string) => call(t.tx.url, { headers: auth(bearer) });
      /** A POST whose body is not JSON at all: the errors Section 6.7 ranks higher must still come first. */
      const garbled = (url: string, bearer?: string) => call(url, { method: 'POST', headers: { ...auth(bearer), 'content-type': 'application/json' }, body: '{' });

      const r = await through('allow', false);
      await says('ready: GET, anonymous', read(r), 200, undefined, r, false);
      await says('ready: GET with the session_token', read(r, r.session), 200, undefined, r, false);
      await says('ready: GET with the transaction_token', read(r, r.token), 200, undefined, r, true);
      await says('ready: GET with a wrong bearer', read(r, rnd(32)), 401, 'invalid_token', r, false);
      await says('ready: second assertion, anonymous', replay(r), 409, 'assertion_replayed', r, false);
      await says('ready: second assertion with the session_token', replay(r, r.session), 409, 'assertion_replayed', r, false);
      await says('ready: second assertion with the transaction_token', replay(r, r.token), 409, 'assertion_replayed', r, true);
      await says('ready: decision with the session_token (invalid_token before invalid_request)', decide(r, r.session), 401, 'invalid_token', r, false);
      await says('ready: decision without a credential and with a malformed body (invalid_token before invalid_request)', decide(r, undefined, { decision: 'maybe' }), 401, 'invalid_token', r, false);
      await says('ready: decision that is not JSON, with the session_token (invalid_token before invalid_request)', garbled(r.reviewUrl, r.session), 401, 'invalid_token', r, false);
      await says('ready: decision with the transaction_token', decide(r, r.token), 400, 'invalid_request', r, true);

      const rd = await through('allow', true);
      await says('ready, deliver_to_session: GET with the session_token', read(rd, rd.session), 200, undefined, rd, true);
      await says('ready, deliver_to_session: GET, anonymous', read(rd), 200, undefined, rd, false);
      await says('ready, deliver_to_session: second assertion with the session_token', replay(rd, rd.session), 409, 'assertion_replayed', rd, true);
      await says('ready, deliver_to_session: second assertion, anonymous', replay(rd), 409, 'assertion_replayed', rd, false);
      await says('ready, deliver_to_session: decision with the session_token', decide(rd, rd.session), 401, 'invalid_token', rd, true);

      const d = await through('deny', false);
      await says('denied: GET, anonymous', read(d), 200, undefined, d, false);
      await says('denied: GET with the session_token', read(d, d.session), 200, undefined, d, false);
      await says('denied: GET with the transaction_token', read(d, d.token), 200, undefined, d, true);
      await says('denied: GET with a wrong bearer', read(d, rnd(32)), 401, 'invalid_token', d, false);
      await says('denied: assertion, anonymous', replay(d), 410, 'transaction_expired', d, false);
      await says('denied: malformed assertion (transaction_expired before invalid_assertion)', call(d.assertUrl, { method: 'POST', json: { assertion: 'nonsense' } }), 410, 'transaction_expired', d, false);
      await says('denied: assertion that is not JSON (transaction_expired before invalid_request)', garbled(d.assertUrl), 410, 'transaction_expired', d, false);
      await says('denied: assertion with the session_token', replay(d, d.session), 410, 'transaction_expired', d, false);
      await says('denied: assertion with the transaction_token', replay(d, d.token), 410, 'transaction_expired', d, true);
      await says('denied: decision with the session_token (invalid_token before transaction_expired)', decide(d, d.session), 401, 'invalid_token', d, false);
      await says('denied: decision without a credential (invalid_token before transaction_expired)', decide(d), 401, 'invalid_token', d, false);
      await says('denied: decision with the transaction_token', decide(d, d.token), 410, 'transaction_expired', d, true);
      await says('denied: decision with the transaction_token and a malformed body (transaction_expired before invalid_request)', decide(d, d.token, { decision: 'maybe' }), 410, 'transaction_expired', d, true);
      await says('denied: decision that is not JSON, with the transaction_token (transaction_expired before invalid_request)', garbled(d.reviewUrl, d.token), 410, 'transaction_expired', d, true);

      const dd = await through('deny', true);
      await says('denied, deliver_to_session: GET with the session_token', read(dd, dd.session), 200, undefined, dd, true);
      await says('denied, deliver_to_session: GET, anonymous', read(dd), 200, undefined, dd, false);
      await says('denied, deliver_to_session: assertion with the session_token', replay(dd, dd.session), 410, 'transaction_expired', dd, true);
      await says('denied, deliver_to_session: decision with the session_token', decide(dd, dd.session), 401, 'invalid_token', dd, true);

      // invalid_transaction comes first: an unknown identifier answers 404 whatever else is wrong with the request.
      const ghostId = rnd();
      const ghost = (u: string) => u.replace(r.tx.transaction_id, ghostId);
      const unknown: Array<[string, () => Promise<Res>]> = [['GET with a bearer', () => call(`${m.transaction_endpoint}/${ghostId}`, { headers: auth(rnd(32)) })]];
      if (r.assertUrl.includes(r.tx.transaction_id)) {
        unknown.push(['malformed assertion with a bearer', () => call(ghost(r.assertUrl), { method: 'POST', headers: auth(rnd(32)), json: { assertion: 1 } })]);
        unknown.push(['assertion that is not JSON', () => garbled(ghost(r.assertUrl))]);
      }
      if (r.reviewUrl.includes(r.tx.transaction_id)) {
        unknown.push(['decision without a credential', () => call(ghost(r.reviewUrl), { method: 'POST', json: { decision: 'allow' } })]);
        unknown.push(['malformed decision with a bearer', () => call(ghost(r.reviewUrl), { method: 'POST', headers: auth(rnd(32)), json: { decision: 'maybe' } })]);
        unknown.push(['decision that is not JSON', () => garbled(ghost(r.reviewUrl))]);
      }
      for (const [name, request] of unknown) {
        const u = await request();
        expect(u.status === 404 && obj(u.json).error === 'invalid_transaction', `unknown transaction, ${name} (invalid_transaction first) → ${u.status} ${obj(u.json).error ?? ''}`);
      }
    });
    await this.check('I-44', 'Decision outside awaiting_consent → 400 (410 when terminal) and the Consent Record is unchanged', async () => {
      const fresh = await this.newAgent(this.ownerId ?? (() => { throw new Skip('needs adminToken'); })());
      const s1 = await this.start(this.client, { prompt: 'none' });
      const a1 = obj((await this.assert(s1.tx, fresh)).json);
      expect(a1.status === 'denied' && a1.reason === 'consent_required', `prompt=none on a first visit → ${a1.status} ${a1.reason ?? ''}`);
      const d1 = await call(`${s1.tx.url}/review`, { method: 'POST', headers: { authorization: `Bearer ${a1.transaction_token}` }, json: { decision: 'allow' } });
      expect(d1.status === 410 && obj(d1.json).error === 'transaction_expired' && obj(d1.json).status === 'denied', `decision on a terminal transaction → ${d1.status} ${d1.text.slice(0, 120)}`);
      const s2 = await this.start(this.client, { scope: 'openid email owner_email' });
      const a2 = obj((await this.assert(s2.tx, fresh)).json);
      expect(a2.status === 'awaiting_owner', `owner scope without accept_disclosure → ${a2.status}`);
      const d2 = await call(`${s2.tx.url}/review`, { method: 'POST', headers: { authorization: `Bearer ${a2.transaction_token}` }, json: { decision: 'allow' } });
      expect(d2.status === 400 && obj(d2.json).error === 'invalid_request' && obj(d2.json).status === 'awaiting_owner', `decision while awaiting_owner → ${d2.status} ${d2.text.slice(0, 120)}`);
      const s3 = await this.start(this.client, { scope: 'openid email' });
      const a3 = obj((await this.assert(s3.tx, fresh)).json);
      expect(a3.status === 'awaiting_consent' && a3.consent_reason === 'first_visit', `refused decisions must not create a Consent Record: ${a3.status} ${a3.consent_reason ?? ''}`);
      const allow = await call(a3.next.url, { method: 'POST', headers: { authorization: `Bearer ${a3.transaction_token}` }, json: { decision: 'allow' } });
      expect(allow.status === 200 && obj(allow.json).status === 'ready', `allow → ${allow.status} ${allow.text.slice(0, 120)}`);
      const s4 = await this.start(this.client, { scope: 'openid email' });
      const a4 = obj((await this.assert(s4.tx, fresh)).json);
      expect(a4.status === 'ready', `the Consent Record covers the next sign-in: ${a4.status} ${a4.consent_reason ?? ''}`);
      const d4 = await call(`${s4.tx.url}/review`, { method: 'POST', headers: { authorization: `Bearer ${a4.transaction_token}` }, json: { decision: 'deny' } });
      expect(d4.status === 400 && obj(d4.json).error === 'invalid_request' && obj(d4.json).status === 'ready', `deny while ready → ${d4.status} ${d4.text.slice(0, 120)}`);
      expect(obj((await this.get(s4.tx, a4.transaction_token)).json).status === 'ready', 'status unchanged by the refused deny');
      const s5 = await this.start(this.client, { scope: 'openid email' });
      const a5 = obj((await this.assert(s5.tx, fresh)).json);
      expect(a5.status === 'ready', `the Consent Record survives the refused deny: ${a5.status} ${a5.consent_reason ?? ''}`);
    });
    await this.check('I-45', 'Owner approval only from a qualifying session: an Owner Credential from the one-time-code sign-in can neither approve, refuse nor grant share_owner; the approval view names a Relay client and its op_policy_uri', async () => {
      const missing: string[] = [];
      const agent = this.ownerId ? await this.newAgent(this.ownerId) : this.agent;
      const asOwner = { authorization: `Bearer ${this.credential}` };
      const claims = (v: Record<string, any>) => Array.isArray(v.requested_owner_claims) && v.requested_owner_claims.includes('owner_email');
      const s = await this.start(this.client, { scope: 'openid email owner_email' });
      const a = obj((await this.assert(s.tx, agent, { accept_disclosure: true })).json);
      expect(a.status === 'awaiting_owner', `owner scope → ${a.status} ${a.reason ?? ''}`);
      const plainRes = await call(`${iss}/owner/transactions/${s.tx.transaction_id}`, { headers: asOwner });
      const plain = obj(plainRes.json);
      expect(plainRes.status === 200 && plain.client?.client_id === this.client.client_id && plain.client?.redirect_host === new URL(this.client.redirect_uri).host && plain.handle === agent.handle && claims(plain), `approval view of a plain client → ${plainRes.status} ${plainRes.text.slice(0, 300)}`);
      expect(plain.client.relay_issuer === undefined && plain.relay === undefined, 'a client without relay_issuer must not be named as a Relay');
      const relay = await this.relay();
      if (!relay) missing.push('the approval view of a Relay client (needs relayIssuer, a Relay whose metadata the issuer can fetch)');
      else {
        const redirect_uri = `${relay.issuer}/upstream/cb-${slug()}`;
        const rc: RegisteredClient = { ...(await this.register({ relay_issuer: relay.issuer, redirect_uris: [redirect_uri] })), redirect_uri };
        const s2 = await this.start(rc, { scope: 'openid email owner_email' });
        const a2 = obj((await this.assert(s2.tx, agent, { accept_disclosure: true })).json);
        expect(a2.status === 'awaiting_owner', `Relay client with an owner scope → ${a2.status} ${a2.reason ?? ''}`);
        const viewRes = await call(`${iss}/owner/transactions/${s2.tx.transaction_id}`, { headers: asOwner });
        const view = obj(viewRes.json);
        expect(viewRes.status === 200 && view.client?.client_id === rc.client_id && view.client?.relay_issuer === relay.issuer && view.relay?.issuer === relay.issuer, `the approval view must name the Relay ${relay.issuer}: ${viewRes.status} ${viewRes.text.slice(0, 300)}`);
        expect(typeof view.relay.notice === 'string' && view.relay.notice.trim().length > 0, 'the approval view of a Relay client must say that it is a Relay and that the Owner Claims are forwarded');
        expect(view.relay.op_policy_uri === relay.policy, `the approval view must show the op_policy_uri of the Relay's metadata (${relay.policy}): ${view.relay.op_policy_uri}`);
        expect(view.client.redirect_host === new URL(redirect_uri).host && view.handle === agent.handle && claims(view), `approval view of the Relay client: ${viewRes.text.slice(0, 300)}`);
      }
      const weak = await this.emailOnlyCredential();
      if (!weak) missing.push('the session rule (needs an Owner Credential from the issuer\'s own one-time-code sign-in: emailOnlyOwnerCredential, or ownerEmailSignIn with adminToken; the bootstrap marker alone is checked as M-2)');
      else await this.approvalRule(weak, 'the Owner Credential of a one-time-code sign-in', agent);
      if (missing.length) throw new Skip(`not run: ${missing.join('; ')}`);
    });
    await this.check('I-46', 'DELETE keys revokes pending and active keys and Delegated Credentials; a disabled Agent cannot assert, exchange or use UserInfo; a re-created handle has no Account, Consent Record, key or Delegated Credential of its predecessor', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const hdr = { authorization: `Bearer ${this.credential}` };
      const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
      const keysUrl = (h: string) => `${m.agents_endpoint}/${encodeURIComponent(h)}/keys`;
      const accountsUrl = (h: string) => `${m.agents_endpoint}/${encodeURIComponent(h)}/accounts`;
      const jwks = createRemoteJWKSet(new URL(m.jwks_uri));

      // DELETE .../keys with an Owner Credential (Section 7.3).
      const a = await this.newAgent(this.ownerId);
      const base = keysUrl(a.handle);
      const pending = await AgentClient.generate(a.handle);
      const en = await call(base, { method: 'POST', headers: hdr, json: { jwk: pending.publicJwk } });
      expect(en.status === 201 && obj(en.json).status === 'pending', `pending key → ${en.status} ${en.text.slice(0, 120)}`);
      const delegated = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: a.handle });
      expect((await call(base, { headers: bearer(delegated.credential) })).status === 200, 'Delegated Credential works before the revocation');
      const del = await call(base, { method: 'DELETE', headers: hdr });
      expect(del.status === 204, `DELETE keys → ${del.status} ${del.text.slice(0, 120)}`);
      const listed = await call(base, { headers: hdr });
      const keys = obj(listed.json).keys as Array<Record<string, any>> | undefined;
      expect(listed.status === 200 && Array.isArray(keys) && keys.every((k) => k.status === 'revoked'), `every key still listed after revoke-all must be revoked: ${listed.status} ${JSON.stringify(keys?.map((k) => k.status))}`);
      const asRevoked = await this.assert((await this.start()).tx, a);
      expect(asRevoked.status === 401 && obj(asRevoked.json).error === 'key_revoked', `assertion with the revoked active key → ${asRevoked.status} ${obj(asRevoked.json).error}`);
      const proof = await call(obj(en.json).proof_url, { method: 'POST', json: { proof: await pending.assertion(iss, { transaction_id: 'x', challenge: obj(en.json).challenge }, {}, { header: { typ: 'agent-login-enrollment+jwt' }, payload: { txn: undefined } }) } });
      expect(proof.status === 401 && obj(proof.json).error === 'key_revoked', `proof with the revoked pending key → ${proof.status} ${obj(proof.json).error}`);
      const dAfter = await call(base, { headers: bearer(delegated.credential) });
      expect(dAfter.status === 401 && obj(dAfter.json).error === 'invalid_token', `Delegated Credential after an Owner's revoke-all → ${dAfter.status} ${dAfter.text.slice(0, 120)}`);

      // A disabled Agent (Section 7.4 table).
      const b = await this.newAgent(this.ownerId);
      const signed = await this.signIn(this.client, b);
      expect(signed.tokenRes.status === 200, 'sign-in before the disable');
      const open = await this.start();
      const oa = obj((await this.assert(open.tx, b)).json);
      expect(oa.status === 'ready', `open transaction before the disable: ${oa.status}`);
      const unredeemed = await this.start();
      const ua = obj((await this.assert(unredeemed.tx, b)).json);
      const code = new URL(obj((await this.cont(ua.next.url, ua.transaction_token)).json).redirect).searchParams.get('code')!;
      const dis = await this.admin(`/admin/agents/${encodeURIComponent(b.handle)}`, { enabled: false }, 'PATCH');
      expect(dis.enabled === false, `disable → ${JSON.stringify(dis)}`);
      const asDisabled = await this.assert((await this.start()).tx, b);
      expect(asDisabled.status === 401 && obj(asDisabled.json).error === 'unknown_key', `assertion by a disabled Agent → ${asDisabled.status} ${obj(asDisabled.json).error}`);
      const ex = await this.exchange(this.client, code, unredeemed.verifier);
      expect(ex.status === 400 && obj(ex.json).error === 'invalid_grant', `code of a disabled Agent → ${ex.status} ${obj(ex.json).error}`);
      const ui = await call(m.userinfo_endpoint, { headers: bearer(signed.token.access_token) });
      expect(ui.status === 401 && /invalid_token/.test(ui.headers.get('www-authenticate') ?? ''), `UserInfo for a disabled Agent → ${ui.status} ${ui.headers.get('www-authenticate')}`);
      const openAfter = obj((await this.get(open.tx, oa.transaction_token)).json);
      expect(openAfter.status === 'denied' && openAfter.reason === 'access_denied', `open transaction of a disabled Agent → ${openAfter.status} ${openAfter.reason ?? ''}`);
      const re = await this.admin(`/admin/agents/${encodeURIComponent(b.handle)}`, { enabled: true }, 'PATCH');
      expect(re.enabled === true && obj((await this.assert((await this.start()).tx, b)).json).status === 'ready', 're-enabled Agent signs in again');

      // Deletion and re-creation: Consent Records and Accounts belong to the Agent, not to the handle (Section 7.4).
      const c = await this.newAgent(this.ownerId);
      const local = c.handle.split('@')[0]!;
      const first = await this.signIn(this.client, c);
      const { payload: p1 } = await jwtVerify(first.token.id_token, jwks, { issuer: iss });
      const before = obj((await call(accountsUrl(c.handle), { headers: hdr })).json).accounts;
      expect(Array.isArray(before) && before.length === 1 && before[0].sign_in_count === 1, `Account before the deletion: ${JSON.stringify(before)}`);
      const dc = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: c.handle });
      expect((await call(keysUrl(c.handle), { headers: bearer(dc.credential) })).status === 200, 'Delegated Credential works before the deletion');
      await this.admin(`/admin/agents/${encodeURIComponent(c.handle)}`, undefined, 'DELETE');
      const gone = await call(keysUrl(c.handle), { headers: hdr });
      expect(gone.status === 404, `management of a deleted Agent → ${gone.status}`);
      expect((await call(m.userinfo_endpoint, { headers: bearer(first.token.access_token) })).status === 401, 'UserInfo after the deletion → 401');
      /** What a successor of `old` under the current Owner Credential must and must not inherit. */
      const successor = async (label: string, old: AgentClient, oldSubs: unknown[], oldDelegated: string, next: AgentClient) => {
        const mine = { authorization: `Bearer ${this.credential}` };
        const inherited = await call(accountsUrl(next.handle), { headers: mine });
        expect(inherited.status === 200 && Array.isArray(obj(inherited.json).accounts) && obj(inherited.json).accounts.length === 0, `${label}: Accounts of the re-created handle → ${inherited.status} ${inherited.text.slice(0, 160)}`);
        const live = obj((await call(keysUrl(next.handle), { headers: mine })).json).keys as Array<Record<string, any>> | undefined;
        expect(Array.isArray(live) && live.filter((k) => k.status === 'active').length === 1 && live.every((k) => k.kid !== old.kid || k.status !== 'active'), `${label}: the re-created handle must hold only its own key: ${JSON.stringify(live?.map((k) => k.status))}`);
        const oldKey = await this.assert((await this.start()).tx, old);
        expect(oldKey.status === 401 && ['unknown_key', 'key_revoked'].includes(obj(oldKey.json).error), `${label}: assertion with the deleted Agent's key → ${oldKey.status} ${obj(oldKey.json).error ?? obj(oldKey.json).status}`);
        const oldCred = await call(keysUrl(next.handle), { headers: bearer(oldDelegated) });
        expect(oldCred.status === 401 || oldCred.status === 404, `${label}: Delegated Credential of the deleted Agent → ${oldCred.status}`);
        const na = obj((await this.assert((await this.start()).tx, next)).json);
        expect(na.status === 'awaiting_consent' && na.consent_reason === 'first_visit', `${label}: the re-created handle must start without a Consent Record: ${na.status} ${na.consent_reason ?? ''}`);
        const signIn = await this.signIn(this.client, next);
        const { payload } = await jwtVerify(signIn.token.id_token, jwks, { issuer: iss, audience: this.client.client_id });
        expect(payload.email === old.handle, `${label}: the same handle is re-created: email ${payload.email}`);
        expect(typeof payload.sub === 'string' && !oldSubs.includes(payload.sub), `${label}: sub must differ for a re-created handle`);
        const accounts = obj((await call(accountsUrl(next.handle), { headers: mine })).json).accounts as Array<Record<string, any>> | undefined;
        expect(Array.isArray(accounts) && accounts.length === 1 && accounts[0]!.client_id === this.client.client_id && accounts[0]!.sign_in_count === 1 && accounts[0]!.status === 'enabled', `${label}: after its first sign-in the re-created handle has one Account counting one sign-in: ${JSON.stringify(accounts)}`);
        return payload;
      };
      // Under the same Owner: a Delegated Credential or key that survived would work again here.
      const c2 = await this.newAgent(this.ownerId, local);
      const p2 = await successor('same Owner', c, [p1.sub], dc.credential, c2);
      const dc2 = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: c2.handle });
      await this.admin(`/admin/agents/${encodeURIComponent(c2.handle)}`, undefined, 'DELETE');
      // Under a second Owner: nothing of the first Owner reaches the handle.
      const owner2 = await this.newOwner('second');
      const saved = this.credential;
      this.credential = owner2.credential;
      try {
        const c3 = await this.newAgent(owner2.owner_id, local);
        const p3 = await successor('second Owner', c2, [p1.sub, p2.sub], dc2.credential, c3);
        expect(typeof p3.owner_sub === 'string' && p3.owner_sub !== p2.owner_sub, 'owner_sub is the second Owner\'s');
        const foreign = await call(keysUrl(c3.handle), { headers: hdr });
        expect(foreign.status === 404, `the first Owner's credential on the handle now owned by another Owner → ${foreign.status}`);
      } finally {
        this.credential = saved;
      }
    });
    await this.check('I-47', 'Delegated Credential: 404 for every operation on a sibling handle, which stays untouched; 403 insufficient_permission with WWW-Authenticate insufficient_scope and no change for permissions or status enabled; disabled permitted', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const sibling = await this.newAgent(this.ownerId);
      const d = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: fresh.handle });
      const hdr = { authorization: `Bearer ${d.credential}` };
      const asOwner = { authorization: `Bearer ${this.credential}` };
      const sib = (p: string) => `${m.agents_endpoint}/${encodeURIComponent(sibling.handle)}${p}`;
      const own = (p: string) => `${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}${p}`;
      const client = encodeURIComponent(this.client.client_id);
      // The sibling gets an Account and a Consent Record first, so that a 404 is told apart from "nothing there".
      await this.signIn(this.client, sibling);
      const siblingOps: Array<[string, () => Promise<Res>]> = [
        ['list keys', () => call(sib('/keys'), { headers: hdr })],
        ['enroll key', async () => call(sib('/keys'), { method: 'POST', headers: hdr, json: { jwk: (await AgentClient.generate(sibling.handle)).publicJwk } })],
        ['get key', () => call(sib(`/keys/${encodeURIComponent(sibling.kid)}`), { headers: hdr })],
        ['update key', () => call(sib(`/keys/${encodeURIComponent(sibling.kid)}`), { method: 'PATCH', headers: hdr, json: { name: 'x' } })],
        ['revoke key', () => call(sib(`/keys/${encodeURIComponent(sibling.kid)}`), { method: 'DELETE', headers: hdr })],
        ['revoke all keys', () => call(sib('/keys'), { method: 'DELETE', headers: hdr })],
        ['list accounts', () => call(sib('/accounts'), { headers: hdr })],
        ['set account status disabled', () => call(sib(`/accounts/${client}`), { method: 'PATCH', headers: hdr, json: { status: 'disabled' } })],
        ['set account status enabled', () => call(sib(`/accounts/${client}`), { method: 'PATCH', headers: hdr, json: { status: 'enabled' } })],
        ['revoke consent', () => call(sib(`/consents/${client}`), { method: 'DELETE', headers: hdr })],
      ];
      for (const [name, fn] of siblingOps) {
        const r = await fn();
        // Re-enabling is not delegable either, and Section 7.8 does not rank that 403 against this 404.
        expect(r.status === 404 || (name === 'set account status enabled' && r.status === 403), `${name} on a sibling handle of the same Owner → ${r.status} ${r.text.slice(0, 120)}`);
      }
      const sibKeys = await call(sib('/keys'), { headers: asOwner });
      const listed = obj(sibKeys.json).keys as Array<Record<string, any>> | undefined;
      expect(sibKeys.status === 200 && Array.isArray(listed) && listed.length === 1 && listed[0]!.kid === sibling.kid && listed[0]!.status === 'active' && listed[0]!.name !== 'x', `the sibling's keys must be untouched by the refused operations: ${JSON.stringify(listed?.map((k) => [k.status, k.name]))}`);
      const sibAccounts = obj((await call(sib('/accounts'), { headers: asOwner })).json).accounts as Array<Record<string, any>> | undefined;
      expect(sibAccounts?.length === 1 && sibAccounts[0]!.client_id === this.client.client_id && sibAccounts[0]!.status === 'enabled', `the sibling's Account must still be enabled: ${JSON.stringify(sibAccounts)}`);
      const sibAgain = obj((await this.assert((await this.start()).tx, sibling)).json);
      expect(sibAgain.status === 'ready', `the sibling's Consent Record and Account must be intact: ${sibAgain.status} ${sibAgain.reason ?? sibAgain.consent_reason ?? ''}`);
      const keyUrl = own(`/keys/${encodeURIComponent(fresh.kid)}`);
      const perm = await call(keyUrl, { method: 'PATCH', headers: hdr, json: { name: 'delegated rename', permissions: { share_owner: true } } });
      expect(perm.status === 403 && obj(perm.json).error === 'insufficient_permission', `permissions via a Delegated Credential → ${perm.status} ${perm.text.slice(0, 120)}`);
      expect(/insufficient_scope/.test(perm.headers.get('www-authenticate') ?? ''), `WWW-Authenticate on the 403: ${perm.headers.get('www-authenticate')}`);
      const k = obj((await call(keyUrl, { headers: hdr })).json);
      expect(k.permissions?.share_owner === false && k.name !== 'delegated rename', 'the refused PATCH must change nothing, not even name');
      const named = await call(keyUrl, { method: 'PATCH', headers: hdr, json: { name: 'delegated name' } });
      expect(named.status === 200 && obj(named.json).name === 'delegated name', `name-only PATCH via a Delegated Credential → ${named.status} ${named.text.slice(0, 120)}`);
      await this.signIn(this.client, fresh);
      const acct = own(`/accounts/${client}`);
      const dis = await call(acct, { method: 'PATCH', headers: hdr, json: { status: 'disabled' } });
      expect(dis.status === 200 && obj(dis.json).status === 'disabled', `disable via a Delegated Credential → ${dis.status} ${dis.text.slice(0, 120)}`);
      const en = await call(acct, { method: 'PATCH', headers: hdr, json: { status: 'enabled' } });
      expect(en.status === 403 && obj(en.json).error === 'insufficient_permission' && /insufficient_scope/.test(en.headers.get('www-authenticate') ?? ''), `enable via a Delegated Credential → ${en.status} ${en.headers.get('www-authenticate')} ${en.text.slice(0, 120)}`);
      const list = obj((await call(own('/accounts'), { headers: hdr })).json).accounts as Array<Record<string, any>> | undefined;
      expect(list?.find((x) => x.client_id === this.client.client_id)?.status === 'disabled', `Account status after the refused enable: ${JSON.stringify(list)}`);
      const none = await call(keyUrl);
      expect(none.status === 401 && /invalid_token/.test(none.headers.get('www-authenticate') ?? ''), `no credential → ${none.status} ${none.headers.get('www-authenticate')}`);
    });
    await this.check('I-48', 'Enrollment refuses non-canonical coordinates and, comparing by decoded point, keys already enrolled or revoked for the handle; relay_issuer needs every redirect URI on exactly its host; unoffered id_token_signed_response_alg refused', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const fresh = await this.newAgent(this.ownerId);
      const base = `${m.agents_endpoint}/${encodeURIComponent(fresh.handle)}/keys`;
      const hdr = { authorization: `Bearer ${this.credential}` };
      const enroll = (jwk: unknown) => call(base, { method: 'POST', headers: hdr, json: { jwk } });
      // Section 6.7 pairs invalid_request with 400; Section 7.2 names no other answer for a refused key.
      const refused = (name: string, r: Res) => expect(r.status === 400 && obj(r.json).error === 'invalid_request', `${name} → ${r.status} ${obj(r.json).error ?? ''} ${r.status === 201 ? `(enrolled as ${obj(r.json).kid})` : ''}`);
      // Another spelling of the same 32 octets: the last of 43 base64url characters carries two unused bits.
      const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      const respell = (s: string) => s.slice(0, -1) + B64[B64.indexOf(s.at(-1)!) ^ 1];
      const sameOctets = (a: string, b: string) => a !== b && Buffer.from(a, 'base64url').equals(Buffer.from(b, 'base64url'));
      const pt = smallXPoint();
      const canonical = { kty: 'EC', crv: 'P-256', x: b64u32(pt.x), y: b64u32(pt.y) };
      const fx = fresh.publicJwk.x!;
      const fy = fresh.publicJwk.y!;
      expect(sameOctets(canonical.x, respell(canonical.x)) && sameOctets(canonical.y, respell(canonical.y)) && sameOctets(fx, respell(fx)) && sameOctets(fy, respell(fy)), 'harness: a respelled coordinate must decode to the same octets');
      const minimal = Buffer.from(pt.x.toString(16).padStart(2, '0'), 'hex');
      // Coordinates that do not decode to exactly 32 octets below the field prime (Section 7.2).
      refused('x + p (the same point, not less than the field prime)', await enroll({ ...canonical, x: b64u32(pt.x + P256.p) }));
      refused('x with a leading zero octet (33 octets)', await enroll({ ...canonical, x: Buffer.concat([Buffer.alloc(1), Buffer.from(canonical.x, 'base64url')]).toString('base64url') }));
      refused(`x in minimal length (${minimal.length} octet)`, await enroll({ ...canonical, x: minimal.toString('base64url') }));
      // A key not seen before under another spelling: refused, or enrolled as the point it decodes to.
      const unseen = await AgentClient.generate(fresh.handle);
      const spelled = await enroll({ ...unseen.publicJwk, x: respell(unseen.publicJwk.x!) });
      expect((spelled.status === 400 && obj(spelled.json).error === 'invalid_request') || (spelled.status === 201 && obj(spelled.json).kid === unseen.kid), `a new key with a respelled coordinate must be refused or enrolled under the thumbprint of its point → ${spelled.status} ${obj(spelled.json).kid ?? obj(spelled.json).error}`);
      const ok = await enroll(canonical);
      expect(ok.status === 201 && obj(ok.json).status === 'pending' && obj(ok.json).kid === (await calculateJwkThumbprint(canonical, 'sha256')), `a canonically encoded key → ${ok.status} ${ok.text.slice(0, 120)}`);
      // Already enrolled, pending.
      refused('pending key again', await enroll(canonical));
      refused('pending key again, members reordered', await enroll({ y: canonical.y, x: canonical.x, crv: 'P-256', kty: 'EC' }));
      refused('pending key again, x respelled', await enroll({ ...canonical, x: respell(canonical.x) }));
      refused('pending key again, y respelled', await enroll({ ...canonical, y: respell(canonical.y) }));
      // Already enrolled, active.
      refused('active key again', await enroll(fresh.publicJwk));
      refused('active key again, x respelled', await enroll({ ...fresh.publicJwk, x: respell(fx) }));
      refused('active key again, y respelled', await enroll({ ...fresh.publicJwk, y: respell(fy) }));
      // Revoked for the handle.
      const other = await AgentClient.generate(fresh.handle);
      const e = await other.enroll(iss, m.agents_endpoint, this.credential);
      expect(e.proof.status === 200, `second key → ${e.enroll.status}/${e.proof.status}`);
      const del = await call(`${base}/${encodeURIComponent(other.kid)}`, { method: 'DELETE', headers: hdr });
      expect(del.status === 204, `revoke → ${del.status}`);
      refused('revoked key again', await enroll(other.publicJwk));
      refused('revoked key again, x respelled', await enroll({ ...other.publicJwk, x: respell(other.publicJwk.x!) }));
      refused('revoked key again, y respelled', await enroll({ ...other.publicJwk, y: respell(other.publicJwk.y!) }));
      const stillRevoked = await this.assert((await this.start()).tx, other);
      expect(stillRevoked.status === 401 && obj(stillRevoked.json).error === 'key_revoked', `the revoked key after the refused re-enrollments → ${stillRevoked.status} ${obj(stillRevoked.json).error}`);
      const active = (obj((await call(base, { headers: hdr })).json).keys as Array<Record<string, any>>).filter((k) => k.status === 'active');
      expect(active.length === 1 && active[0]!.kid === fresh.kid, `the handle must still have one active key: ${JSON.stringify(active.map((k) => k.kid))}`);

      // Section 4.4: every redirect URI of a relay_issuer registration is on exactly the Relay's host.
      const reg = (meta: Record<string, unknown>) => call(m.registration_endpoint, { method: 'POST', headers: { authorization: `Bearer ${this.o.adminToken}` }, json: { redirect_uris: ['https://rp-reg.example/cb'], client_name: 'I-48', token_endpoint_auth_method: 'client_secret_basic', ...meta } });
      const relay = await this.relay();
      const relayIss = relay?.issuer ?? `https://relay-${slug()}.example`;
      const rh = new URL(relayIss);
      const port = rh.port ? `:${rh.port}` : '';
      const lookalikes: Array<[string, string]> = [
        ['another host', 'https://rp-reg.example/cb'],
        ['a host that ends with the Relay\'s', `https://evil-${rh.hostname}${port}/cb`],
        ['a subdomain of the Relay\'s host', `https://sub.${rh.hostname}${port}/cb`],
        ['a host that starts with the Relay\'s', `https://${rh.hostname}.evil.example${port}/cb`],
        ['another host with the Relay\'s in the path', `https://evil.example/${rh.host}/cb`],
        ['another host with the Relay\'s as userinfo', `https://${rh.host}@evil.example/cb`],
      ];
      for (const [name, uri] of lookalikes) {
        for (const uris of [[uri], [`${relayIss}/cb`, uri]]) {
          const r = await reg({ relay_issuer: relayIss, redirect_uris: uris });
          expect(r.status === 400 && obj(r.json).error === 'invalid_client_metadata', `relay_issuer with a redirect_uri on ${name} (${uri})${uris.length > 1 ? ', beside one on its host' : ''} → ${r.status} ${r.text.slice(0, 120)}`);
        }
      }
      if (relay) {
        const onHost = await reg({ relay_issuer: relay.issuer, redirect_uris: [`${relay.issuer}/cb`, `${relay.issuer}/cb2`] });
        expect(onHost.status === 201 && obj(onHost.json).relay_issuer === relay.issuer, `relay_issuer with redirect URIs on its host → ${onHost.status} ${obj(onHost.json).error ?? ''} ${obj(onHost.json).error_description ?? ''}`);
      }

      // Section 3.2: id_token_signed_response_alg is ES256, an advertised EdDSA, or refused.
      const offered: string[] = (m.id_token_signing_alg_values_supported as string[]).filter((alg) => alg === 'ES256' || alg === 'EdDSA');
      for (const alg of ['RS256', 'none', 'HS256', 'PS256', 'ES384', 'EdDSA', 'es256'].filter((x) => !offered.includes(x))) {
        const r = await reg({ id_token_signed_response_alg: alg });
        expect(r.status === 400 && obj(r.json).error === 'invalid_client_metadata', `id_token_signed_response_alg ${alg} → ${r.status} ${r.text.slice(0, 120)}`);
      }
      for (const alg of offered) {
        const r = await reg({ id_token_signed_response_alg: alg });
        expect(r.status === 201, `id_token_signed_response_alg ${alg} → ${r.status} ${obj(r.json).error ?? ''}`);
      }
      if (!relay) throw new Skip('enrollment and id_token_signed_response_alg parts passed; not run: acceptance of a relay_issuer registration on the Relay\'s host, without which its refusals prove little (needs relayIssuer, a Relay whose metadata the issuer can fetch)');
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
      await this.signIn(this.client, sibling);
      const sibAcct = `${m.agents_endpoint}/${encodeURIComponent(sibling.handle)}/accounts/${encodeURIComponent(this.client.client_id)}`;
      const sibDis = await call(sibAcct, { method: 'PATCH', headers: hdr, json: { status: 'disabled' } });
      expect(sibDis.status === 404, `disable of a sibling's Account → ${sibDis.status}`);
      const sibAccounts = obj((await call(`${m.agents_endpoint}/${encodeURIComponent(sibling.handle)}/accounts`, { headers: { authorization: `Bearer ${this.credential}` } })).json).accounts as Array<Record<string, any>> | undefined;
      expect(sibAccounts?.length === 1 && sibAccounts[0]!.status === 'enabled', `the sibling's Account is untouched: ${JSON.stringify(sibAccounts)}`);
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
    await this.check('M-2', 'Reference bootstrap session_auth: an Owner Credential marked email_only, or with no stated session, neither approves nor grants share_owner; passkey, oidc, domain and email_factor do', async () => {
      if (!this.ownerId) throw new Skip('needs adminToken');
      const mint = (session_auth?: string) => this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'owner', ...(session_auth ? { session_auth } : {}) });
      const agent = await this.newAgent(this.ownerId);
      const weak = await mint('email_only');
      expect(weak.session_auth === 'email_only' && typeof weak.credential === 'string', `the bootstrap API does not record how the credential's session was established: session_auth ${weak.session_auth}`);
      await this.approvalRule(weak.credential, 'an Owner Credential marked email_only', agent, true);
      const unstated = await mint();
      expect(unstated.session_auth === 'email_only', `an Owner Credential whose session is not stated must fail closed: session_auth ${unstated.session_auth}`);
      await this.approvalRule(unstated.credential, 'an Owner Credential with no stated session', agent, true);
      const keyUrl = `${m.agents_endpoint}/${encodeURIComponent(agent.handle)}/keys/${encodeURIComponent(agent.kid)}`;
      for (const session_auth of ['passkey', 'oidc', 'domain', 'email_factor']) {
        const c = await mint(session_auth);
        for (const share_owner of [true, false]) {
          const r = await call(keyUrl, { method: 'PATCH', headers: { authorization: `Bearer ${c.credential}` }, json: { permissions: { share_owner } } });
          expect(r.status === 200 && obj(r.json).permissions?.share_owner === share_owner, `share_owner ${share_owner} from a ${session_auth} session → ${r.status} ${obj(r.json).error ?? ''}`);
        }
        const s = await this.start(this.client, { scope: 'openid email owner_email' });
        const a = obj((await this.assert(s.tx, agent, { accept_disclosure: true })).json);
        const ok = await call(`${iss}/owner/transactions/${s.tx.transaction_id}/decision`, { method: 'POST', headers: { authorization: `Bearer ${c.credential}` }, json: { decision: 'approve' } });
        expect(a.status === 'awaiting_owner' && ok.status === 200 && obj(ok.json).status === 'ready', `approval from a ${session_auth} session → ${a.status}, ${ok.status} ${obj(ok.json).status ?? obj(ok.json).error ?? ''}`);
      }
    });
    await this.check('I-49', 'Cache-Control: no-store on every response of the run from the endpoints of Sections 5 to 7, redirects included; Pragma: no-cache on the Token Response; never Access-Control-Allow-Credentials: true; auth_time is the time of the assertion when max_age was sent', async () => {
      const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
      const preflights: Array<[string, Res]> = [];
      // Every request of this check is a cross-origin one; the rest of the run sent none.
      this.cx.headers = { origin: 'https://agent.example' };
      try {
        // Section 5: the Authentication Request on its paths, with the failures of steps 1 to 3.
        const s = await this.start();
        await call(m.authorization_endpoint, { method: 'POST', form: Object.fromEntries(new URL(this.authUrl(this.client).url).searchParams) });
        const h = await call(this.authUrl(this.client).url, { headers: { accept: 'text/html' } });
        if (h.status === 303 && h.headers.get('location')) await call(new URL(h.headers.get('location')!, m.authorization_endpoint).href, { headers: { accept: 'text/html', cookie: (h.headers.get('set-cookie') ?? '').split(';')[0]! } });
        for (const accept of ['application/json', 'text/html']) {
          await call(this.authUrl(this.client, { nonce: undefined }).url, { headers: { accept } });
          await call(this.authUrl(this.client, { redirect_uri: 'https://attacker.example/cb' }).url, { headers: { accept } });
          await call(this.authUrl({ ...this.client, client_id: `unknown-${rnd(4)}` }).url, { headers: { accept } });
        }
        // Section 6: the transaction, its errors, the review and the continue step.
        preflights.push(['transaction endpoint', await call(s.tx.next.url, { method: 'OPTIONS', headers: { 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type' } })]);
        await this.get(s.tx);
        await this.get(s.tx, rnd(32));
        await call(`${m.transaction_endpoint}/${rnd()}`);
        await call(s.tx.next.url, { method: 'POST', json: { assertion: 'nonsense' } });
        const reviewed = await this.start(this.client, { prompt: 'consent' });
        const ra = obj((await this.assert(reviewed.tx, this.agent)).json);
        expect(ra.status === 'awaiting_consent', `prompt=consent → ${ra.status} ${ra.reason ?? ''}`);
        await call(ra.next.url, { method: 'POST', json: { decision: 'allow' } });
        await call(ra.next.url, { method: 'POST', headers: bearer(ra.transaction_token), json: { decision: 'maybe' } });
        await call(ra.next.url, { method: 'POST', headers: bearer(ra.transaction_token), json: { decision: 'allow' } });
        const t = obj((await this.assert(s.tx, this.agent, { accept_disclosure: true })).json);
        expect(t.status === 'ready', `assertion → ${t.status} ${t.reason ?? ''}`);
        await this.assert(s.tx, this.agent);
        await call(t.next.url);
        const c = await this.cont(t.next.url, t.transaction_token);
        expect(c.status === 200 && typeof obj(c.json).redirect === 'string', `continue → ${c.status} ${obj(c.json).error ?? ''}`);
        await this.cont(t.next.url, t.transaction_token);
        const code = new URL(obj(c.json).redirect).searchParams.get('code')!;
        const tok = await this.exchange(this.client, code, s.verifier);
        expect(tok.status === 200 && /no-cache/i.test(tok.headers.get('pragma') ?? ''), `Token Response → ${tok.status}, Pragma "${tok.headers.get('pragma')}"`);
        await this.exchange(this.client, code, s.verifier);
        await call(m.token_endpoint, { method: 'POST', form: { grant_type: 'authorization_code', code, redirect_uri: this.client.redirect_uri, code_verifier: s.verifier, client_id: this.client.client_id, client_secret: 'wrong' } });
        await call(m.userinfo_endpoint, { headers: bearer(obj(tok.json).access_token) });
        await call(m.userinfo_endpoint);
        const s2 = await this.start();
        await this.assert(s2.tx, this.agent, { accept_disclosure: true, deliver_to_session: true });
        const released = obj((await this.get(s2.tx, s2.tx.session_token)).json);
        expect(typeof released.next?.url === 'string', `continue URL for the Session Holder after deliver_to_session: ${released.status}`);
        await call(released.next.url, { headers: { accept: 'text/html', ...bearer(s2.tx.session_token) } });
        // Section 7: management, with its refusals. Destructive operations only on an Agent the harness created.
        const subject = this.ownerId ? await this.newAgent(this.ownerId) : this.agent;
        const agentUrl = `${m.agents_endpoint}/${encodeURIComponent(subject.handle)}`;
        const hdr = bearer(this.credential);
        preflights.push(['agents endpoint', await call(`${agentUrl}/keys`, { method: 'OPTIONS', headers: { 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type' } })]);
        const k = await AgentClient.generate(subject.handle);
        await call(`${agentUrl}/keys`, { method: 'POST', headers: hdr, json: { jwk: { ...k.publicJwk, use: 'sig' } } });
        const en = await call(`${agentUrl}/keys`, { method: 'POST', headers: hdr, json: { jwk: k.publicJwk } });
        expect(en.status === 201, `enroll → ${en.status} ${obj(en.json).error ?? ''}`);
        const proof = await k.assertion(iss, { transaction_id: 'x', challenge: obj(en.json).challenge }, {}, { header: { typ: 'agent-login-enrollment+jwt' }, payload: { txn: undefined } });
        await call(obj(en.json).proof_url, { method: 'POST', json: { proof: 'nonsense' } });
        await call(obj(en.json).proof_url, { method: 'POST', json: { proof } });
        await call(obj(en.json).proof_url, { method: 'POST', json: { proof } });
        await call(`${agentUrl}/keys`, { headers: hdr });
        await call(`${agentUrl}/keys/${encodeURIComponent(k.kid)}`, { headers: hdr });
        await call(`${agentUrl}/keys/${encodeURIComponent(k.kid)}`, { method: 'PATCH', headers: hdr, json: { name: 'I-49' } });
        await call(`${agentUrl}/keys/${encodeURIComponent(k.kid)}`, { method: 'DELETE', headers: hdr });
        await call(`${agentUrl}/accounts`, { headers: hdr });
        await call(`${agentUrl}/keys`);
        await call(`${m.agents_endpoint}/${encodeURIComponent(`nobody-${slug()}@${subject.handle.split('@')[1]}`)}/keys`, { headers: hdr });
        if (this.ownerId) {
          await this.signIn(this.client, subject);
          const account = `${agentUrl}/accounts/${encodeURIComponent(this.client.client_id)}`;
          const delegated = await this.admin('/admin/credentials', { owner_id: this.ownerId, kind: 'delegated', handle: subject.handle });
          await call(account, { method: 'PATCH', headers: hdr, json: { status: 'disabled' } });
          await call(account, { method: 'PATCH', headers: bearer(delegated.credential), json: { status: 'enabled' } });
          await call(account, { method: 'PATCH', headers: hdr, json: { status: 'enabled' } });
          await call(`${agentUrl}/keys/${encodeURIComponent(subject.kid)}`, { method: 'PATCH', headers: bearer(delegated.credential), json: { permissions: { share_owner: true } } });
          await call(`${agentUrl}/consents/${encodeURIComponent(this.client.client_id)}`, { method: 'DELETE', headers: hdr });
          await call(`${agentUrl}/keys`, { method: 'DELETE', headers: hdr });
        }
        if (this.o.adminToken) {
          await call(m.registration_endpoint, { method: 'POST', headers: bearer(this.o.adminToken), json: { redirect_uris: ['https://rp-cache.example/cb'], token_endpoint_auth_method: 'client_secret_basic' } });
          await call(m.registration_endpoint, { method: 'POST', headers: bearer(this.o.adminToken), json: { redirect_uris: ['https://rp-cache.example/cb'], token_endpoint_auth_method: 'none' } });
          await call(m.registration_endpoint, { method: 'POST', json: { redirect_uris: ['https://rp-cache.example/cb'], token_endpoint_auth_method: 'client_secret_basic' } });
        }
      } finally {
        this.cx.headers = undefined;
      }

      // The audit: every response the run received from these endpoints, whichever check asked for it.
      const bare = (u: string) => u.split(/[?#]/)[0]!;
      const waitPages = new Set(this.seen.filter((x) => bare(x.url) === m.authorization_endpoint && x.status === 303 && x.location).map((x) => bare(new URL(x.location!, x.url).href)).filter((u) => u.startsWith(`${iss}/`)));
      const endpoints = [m.authorization_endpoint, m.transaction_endpoint, m.token_endpoint, m.userinfo_endpoint, m.registration_endpoint, m.agents_endpoint, `${iss}/owner`].filter((e): e is string => typeof e === 'string');
      const audited = this.seen.filter((x) => endpoints.some((e) => bare(x.url) === e || bare(x.url).startsWith(`${e}/`)) || waitPages.has(bare(x.url)));
      // Long path segments are secrets or identifiers (continue URLs must stay out of logs): shortened.
      const brief = (x: Seen) => `${x.check} ${x.method} ${new URL(x.url).pathname.split('/').map((seg) => (seg.length > 30 ? `${seg.slice(0, 6)}…` : seg)).join('/')} (${x.status})`;
      const stale = audited.filter((x) => !(x.cacheControl ?? '').toLowerCase().split(',').map((d) => d.trim()).includes('no-store'));
      expect(audited.length > 0 && stale.length === 0, `${stale.length} of ${audited.length} responses lack Cache-Control: no-store: ${stale.slice(0, 6).map((x) => `${brief(x)} "${x.cacheControl ?? ''}"`).join('; ')}`);
      const credentialed = this.seen.filter((x) => x.url.startsWith(`${iss}/`) && (x.allowCredentials ?? '').trim().toLowerCase() === 'true');
      expect(credentialed.length === 0, `${credentialed.length} responses set Access-Control-Allow-Credentials: true: ${credentialed.slice(0, 6).map(brief).join('; ')}`);
      // Section 6 requires the preflights of an Issuer that supports browser-based Agent Clients; one that answers neither offers no CORS.
      const answered = preflights.filter(([, r]) => r.status < 400 && !!r.headers.get('access-control-allow-origin'));
      if (answered.length > 0) for (const [name, r] of preflights) expect(answered.some(([n]) => n === name), `CORS is offered on the ${answered[0]![0]}, so the preflight of the ${name} must be answered too: ${r.status}, Access-Control-Allow-Origin "${r.headers.get('access-control-allow-origin')}"`);

      // auth_time (Section 3.1) is the time the assertion was accepted: not when the transaction was created, 2.5 s
      // earlier, and not when the token was issued, 1.5 s later. It is compared with iat, so that both readings come from
      // the Issuer's clock, against what the harness's clock allows for the same interval: no tolerance to tune.
      const s3 = await this.start(this.client, { max_age: '300' });
      await sleep(2500);
      const a0 = Date.now();
      const a3 = obj((await this.assert(s3.tx, this.agent, { accept_disclosure: true })).json);
      const a1 = Date.now();
      expect(a3.status === 'ready', `assertion on a request with max_age → ${a3.status} ${a3.reason ?? ''}`);
      await sleep(1500);
      const c3 = new URL(obj((await this.cont(a3.next.url, a3.transaction_token)).json).redirect);
      const e0 = Date.now();
      const t3 = await this.exchange(this.client, c3.searchParams.get('code')!, s3.verifier);
      const e1 = Date.now();
      expect(t3.status === 200, `exchange after a request with max_age → ${t3.status} ${obj(t3.json).error ?? ''}`);
      const { payload } = await jwtVerify(obj(t3.json).id_token, createRemoteJWKSet(new URL(m.jwks_uri)), { issuer: iss, audience: this.client.client_id });
      expect(typeof payload.auth_time === 'number', `auth_time is REQUIRED when the request carried max_age: ${payload.auth_time}`);
      // The assertion was accepted between a0 and a1 and the token issued between e0 and e1; whole seconds add or lose up to one.
      const gap = payload.iat! - (payload.auth_time as number);
      const least = (e0 - a1) / 1000 - 1;
      const most = (e1 - a0) / 1000 + 1;
      expect(gap > least && gap < most, `auth_time must be the time the assertion was accepted: the token was issued ${((e0 - a1) / 1000).toFixed(1)} to ${((e1 - a0) / 1000).toFixed(1)} s after the assertion, but iat - auth_time is ${gap} s`);
    });

    return this.report();
  }
  private report(): Report {
    const passed = this.results.filter((r) => r.outcome === 'pass').length;
    const failed = this.results.filter((r) => r.outcome === 'fail').length;
    const skipped = this.results.filter((r) => r.outcome === 'skip').length;
    return { issuer: this.o.issuer, results: this.results, passed, failed, skipped };
  }
}

class Skip extends Error {}
function expect(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message);
}

/** P-256 field prime and curve coefficient b (Section 7.2: coordinates must be less than the field prime). */
const P256 = {
  p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
};
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}
/** An upper bound on the entropy of an identifier, from the alphabet it uses: a UUID carries 122 bits, hexadecimal 4 bits and base64url 6 bits a character. */
function entropyBits(v: unknown): number {
  if (typeof v !== 'string') return 0;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return 122;
  if (/^[0-9a-f]+$/i.test(v)) return v.length * 4;
  if (/^[0-9]+$/.test(v)) return Math.floor(v.length * 3.33);
  return v.replace(/[^A-Za-z0-9_-]/g, '').length * 6;
}
/** 32-octet big-endian base64url encoding of a coordinate. */
const b64u32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').toString('base64url');
/**
 * A P-256 point with a small x coordinate, so that x + p still fits in 32 octets and encodes the same point
 * non-canonically. The search starts at a random x: every run uses a key the issuer has not seen, so the harness
 * can be run again against an issuer that keeps its state.
 */
function smallXPoint(): { x: bigint; y: bigint } {
  const { p, b } = P256;
  for (let x = BigInt(`0x${randomBytes(20).toString('hex')}`) + 1n; ; x += 1n) {
    const rhs = (((x * x * x - 3n * x + b) % p) + p) % p;
    const y = modPow(rhs, (p + 1n) / 4n, p); // p ≡ 3 (mod 4)
    if ((y * y) % p === rhs) return { x, y };
  }
}

export async function runConformance(o: HarnessOptions): Promise<Report> {
  return new Harness(o).run();
}
export { AgentClient };
