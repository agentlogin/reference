// Client behaviour reported against commit 84e5f3f: cookie scope, lost enrollment responses, the sign-in deadline,
// and local key records of several issuers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { serve } from '@hono/node-server';
import { createIssuer } from '../../issuer/src/index.js';
import { AgentLogin, AgentLoginError, MemoryCookieJar, MemoryKeystore } from '../src/index.js';

const rnd = (n = 16) => randomBytes(n).toString('base64url');
async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}
/** A reference issuer on a loopback port. `tamper` may replace a response after the issuer has processed the request. */
async function issuer(tamper?: (req: Request, res: Response) => Response | undefined) {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const { app } = await createIssuer({ issuer: url, handleDomains: ['example.com'], allowInsecureClients: true, adminToken: 'admin' });
  const server = serve({ port, hostname: '127.0.0.1', fetch: async (req: Request) => { const res = await app.fetch(req); return tamper?.(req, res) ?? res; } });
  await new Promise((r) => setTimeout(r, 30));
  const post = async (path: string, body: unknown, token = 'admin') => (await (await fetch(`${url}${path}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()) as Record<string, any>;
  const owner = await post('/admin/owners', { email: `o-${rnd(4)}@example.org`, name: 'Jane', session_auth: 'passkey' });
  await post('/admin/agents', { handle: 'scout@example.com', owner_id: owner.owner_id, name: 'Scout' });
  const client = await post('/register', { redirect_uris: ['https://rp.example/cb'], client_name: 'RP', tos_uri: 'https://rp.example/t', policy_uri: 'https://rp.example/p', token_endpoint_auth_method: 'client_secret_basic' });
  const authUrl = (scope = 'openid email') => `${url}/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: 'https://rp.example/cb', scope, state: rnd(), nonce: rnd(), code_challenge: createHash('sha256').update(rnd(32)).digest('base64url'), code_challenge_method: 'S256' })}`;
  return { url, owner, post, authUrl, close: () => new Promise<void>((r) => server.close(() => r())) };
}
const agentFor = (iss: { url: string }, keystore = new MemoryKeystore()) => ({ keystore, al: new AgentLogin({ handle: 'scout@example.com', issuer: iss.url, allowInsecure: true, keystore, cookies: new MemoryCookieJar() }) });

test('#6 a cookie without Path is scoped to the directory of the URL that set it', async () => {
  const jar = new MemoryCookieJar();
  await jar.store(new URL('https://app.example/private/login'), ['a=1', 'b=2; Path=/', 'c=3; Path=/private/sub', 'd=4; Path=relative']);
  await jar.store(new URL('https://app.example/top'), ['e=5']);
  await jar.store(new URL('https://app.example/x/y/z'), ['f=6']);
  const sent = async (path: string) => ((await jar.header(new URL(`https://app.example${path}`))) ?? '').split('; ').filter(Boolean).sort().join(' ');
  assert.equal(await sent('/public/echo'), 'b=2 e=5', 'a cookie set under /private is not sent to /public');
  assert.equal(await sent('/private/account'), 'a=1 b=2 d=4 e=5');
  assert.equal(await sent('/private'), 'a=1 b=2 d=4 e=5');
  assert.equal(await sent('/privateer'), 'b=2 e=5', '/private is not a prefix of /privateer');
  assert.equal(await sent('/private/sub/deep'), 'a=1 b=2 c=3 d=4 e=5');
  assert.equal(await sent('/x/y/other'), 'b=2 e=5 f=6');
  assert.equal(await sent('/x/other'), 'b=2 e=5');
});

test('#7 an enrollment whose response is lost keeps its private key and is reconciled', async () => {
  let lose: 'proof' | 'proof-and-status' | undefined;
  const iss = await issuer((req, res) => {
    const path = new URL(req.url).pathname;
    if (lose && path.endsWith('/proof') && res.status === 200) {
      if (lose === 'proof') lose = undefined;
      return new Response('bad gateway', { status: 502 }); // the issuer accepted the proof; the answer never arrives
    }
    if (lose === 'proof-and-status' && req.method === 'GET' && /\/keys\/[^/]+$/.test(path)) return new Response('bad gateway', { status: 502 });
    return undefined;
  });
  try {
    // The proof's answer is lost, the issuer can be asked: the client finds the key active and keeps it.
    lose = 'proof';
    const first = agentFor(iss);
    const key = await first.al.enroll({ credential: iss.owner.credential });
    assert.equal(key.status, 'active');
    assert.equal((await first.keystore.get(key.kid))?.status, 'active');
    const r = await first.al.signIn({ authorizationUrl: iss.authUrl(), expectedHost: 'rp.example' });
    assert.equal(r.client.redirect_host, 'rp.example');

    // The answer is lost and the issuer cannot be asked either: the outcome is unknown, so the key is kept.
    lose = 'proof-and-status';
    const second = agentFor(iss);
    const err = await second.al.enroll({ credential: iss.owner.credential }).catch((e: unknown) => e as AgentLoginError);
    assert.ok(err instanceof AgentLoginError && err.code === 'enrollment_uncertain', `error ${(err as Error).message}`);
    const kept = await second.keystore.list('scout@example.com');
    assert.equal(kept.length, 1, 'the private key is still there');
    assert.equal(kept[0]!.status, 'pending');
    lose = undefined;
    const settled = await second.al.reconcileKeys(iss.owner.credential);
    assert.deepEqual(settled, { activated: 1, removed: 0, pending: 0 });
    assert.equal((await second.keystore.get(kept[0]!.kid))?.status, 'active');
    await second.al.signIn({ authorizationUrl: iss.authUrl(), expectedHost: 'rp.example' });

    // A definite refusal still removes the key that will never be enrolled.
    const third = agentFor(iss);
    await assert.rejects(third.al.enroll({ credential: 'not-a-credential' }), (e: unknown) => e instanceof AgentLoginError && e.status === 401);
    assert.equal((await third.keystore.list('scout@example.com')).length, 0);
  } finally {
    await iss.close();
  }
});

test('#10 a sign-in does not outlive its deadline', async () => {
  const iss = await issuer();
  try {
    const { al } = agentFor(iss);
    await al.enroll({ credential: iss.owner.credential });
    // owner_email without share_owner waits for the Owner; the Owner approves after the deadline has passed.
    const started = Date.now();
    let pending = '';
    const err = await al.signIn({
      authorizationUrl: iss.authUrl('openid email owner_email'),
      expectedHost: 'rp.example',
      deadlineMs: 150,
      onOwnerApproval: (t) => {
        pending = t.transaction_id;
        setTimeout(() => { void iss.post(`/owner/transactions/${t.transaction_id}/decision`, { decision: 'approve' }, iss.owner.credential); }, 300);
      },
    }).catch((e: unknown) => e as AgentLoginError);
    const elapsed = Date.now() - started;
    assert.ok(err instanceof AgentLoginError && err.code === 'timeout', `expected a timeout, got ${err instanceof Error ? err.message : 'success'}`);
    assert.ok(elapsed < 900, `gave up after ${elapsed} ms for a 150 ms deadline`);
    assert.ok(pending, 'the Owner was asked');
    // the transaction was not completed behind the caller's back
    await new Promise((r) => setTimeout(r, 400));
    const tx = (await (await fetch(`${iss.url}/transactions/${pending}`)).json()) as { status: string };
    assert.notEqual(tx.status, 'completed');
  } finally {
    await iss.close();
  }
});

test('#11 revoking at one issuer leaves the local keys of another issuer alone', async () => {
  const a = await issuer();
  const b = await issuer();
  try {
    const keystore = new MemoryKeystore();
    const atA = agentFor(a, keystore).al;
    const atB = agentFor(b, keystore).al;
    const keyA = await atA.enroll({ credential: a.owner.credential });
    const keyB = await atB.enroll({ credential: b.owner.credential });
    await atB.revokeKey(b.owner.credential); // every key of the handle, at issuer B
    assert.equal((await keystore.get(keyB.kid))?.status, 'revoked');
    assert.equal((await keystore.get(keyA.kid))?.status, 'active', 'the key enrolled at issuer A is untouched');
    await atA.signIn({ authorizationUrl: a.authUrl(), expectedHost: 'rp.example' });
  } finally {
    await a.close();
    await b.close();
  }
});
