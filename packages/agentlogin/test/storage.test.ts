// Regression tests for the client's local storage and discovery (reported against commit 9b6dd09).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FileCookieJar, FileKeystore, acctUri, fetchMetadata, freshness, parseHandle, safeFetch, webfingerUrl } from '../src/index.js';
import { chainFreshness } from '../src/discovery.js';
import { withFileLock, writePrivateJson } from '../src/files.js';

const run = (file: string, args: string[], env: Record<string, string>) =>
  new Promise<{ code: number; stderr: string }>((resolve) => {
    execFile(process.execPath, ['--import', 'tsx', file, ...args], { env: { PATH: process.env.PATH ?? '', ...env } }, (err, _out, stderr) => resolve({ code: err ? 1 : 0, stderr }));
  });

test('#3 each Agent has its own cookie jar; local parts are case-sensitive', async () => {
  process.env.AGENTLOGIN_HOME = mkdtempSync(join(tmpdir(), 'al-jar-'));
  const lower = FileCookieJar.forHandle('scout@example.com');
  const upper = FileCookieJar.forHandle('Scout@example.com');
  assert.notEqual(lower.path.toLowerCase(), upper.path.toLowerCase(), 'distinct even on a case-insensitive file system');
  assert.equal(FileCookieJar.forHandle('scout@EXAMPLE.com').path, lower.path, 'the domain is case-insensitive');
  assert.match(basename(lower.path), /^[0-9a-f]{64}\.json$/);
  await lower.store(new URL('https://app.example.org/'), ['sid=lower; Path=/']);
  assert.equal(await upper.header(new URL('https://app.example.org/')), undefined);
  assert.equal(await lower.header(new URL('https://app.example.org/')), 'sid=lower');
  assert.throws(() => FileCookieJar.forHandle('not a handle'));
});

test('#4 concurrent processes do not lose keys or cookies', async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-conc-'));
  const worker = fileURLToPath(new URL('./storage-worker.ts', import.meta.url));
  const procs = 8;
  const each = 25;
  const results = await Promise.all(Array.from({ length: procs }, (_, i) => run(worker, [String(i), String(each)], { AGENTLOGIN_HOME: home })));
  for (const r of results) assert.equal(r.code, 0, r.stderr);
  const keys = await new FileKeystore(join(home, 'keys.json')).list();
  assert.equal(keys.length, procs * each, `keys kept: ${keys.length}`);
  const cookies = JSON.parse(readFileSync(FileCookieJar.forHandle('scout@example.com').path.replace(process.env.AGENTLOGIN_HOME ?? '\u0000', home), 'utf8')) as unknown[];
  assert.equal(cookies.length, procs * each, `cookies kept: ${cookies.length}`);
});

test('#5 Issuer metadata honours HTTP freshness and does not cross security modes', async () => {
  let hits = 0;
  let cacheControl = 'no-store';
  let base = '';
  const srv = http.createServer((req, res) => {
    if (req.url === '/.well-known/openid-configuration') {
      hits += 1;
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': cacheControl });
      res.end(JSON.stringify({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, userinfo_endpoint: `${base}/userinfo`, jwks_uri: `${base}/jwks`, transaction_endpoint: `${base}/transactions`, agents_endpoint: `${base}/agents`, handle_domains: ['example.com'], agent_key_algs_supported: ['ES256'], agent_login_versions_supported: ['1.0'] }));
    } else { res.writeHead(404); res.end(); }
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    await fetchMetadata(base, { allowInsecure: true });
    await fetchMetadata(base, { allowInsecure: true });
    assert.equal(hits, 2, 'no-store: fetched each time');
    cacheControl = 'max-age=0';
    await fetchMetadata(base, { allowInsecure: true });
    await fetchMetadata(base, { allowInsecure: true });
    assert.equal(hits, 4, 'max-age=0: fetched each time');
    cacheControl = 'max-age=60';
    await fetchMetadata(base, { allowInsecure: true });
    await fetchMetadata(base, { allowInsecure: true });
    assert.equal(hits, 5, 'max-age=60: served from cache');
    // What development mode accepted is not handed to a caller in secure mode.
    await assert.rejects(fetchMetadata(base), /invalid issuer identifier/);
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
  }
});

test('#8 the WebFinger query carries the acct URI with its userpart percent-encoded', () => {
  const cases: Array<[string, string]> = [
    ['scout@example.com', 'acct:scout@example.com'],
    ['qa#bot@example.com', 'acct:qa%23bot@example.com'],
    ['agent%test@example.com', 'acct:agent%25test@example.com'],
    ['a/b?c@example.com', 'acct:a%2Fb%3Fc@example.com'],
    ["o'neil+x@example.com", "acct:o'neil+x@example.com"],
    ['x^y`z{w|v}@EXAMPLE.com', 'acct:x%5Ey%60z%7Bw%7Cv%7D@example.com'],
  ];
  for (const [handle, uri] of cases) {
    assert.equal(acctUri(parseHandle(handle)!.handle), uri);
    const url = webfingerUrl(handle);
    assert.equal(url.searchParams.get('resource'), uri, 'decoded once, the query value is the acct URI');
    assert.equal(url.host, 'example.com');
  }
  // On the wire the URI's own percent sign is encoded again: %23 becomes %2523.
  assert.ok(webfingerUrl('qa#bot@example.com').href.includes('resource=acct%3Aqa%2523bot%40example.com'));
});

const key = (kid: string) => ({ kid, handle: 'scout@example.com', issuer: 'https://issuer.example', privateJwk: { kty: 'EC' }, publicJwk: { kty: 'EC' }, createdAt: 0, status: 'active' as const });

test('lock: a dead holder is taken over at once, and concurrent waiters lose nothing', async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-dead-'));
  const file = join(home, 'keys.json');
  writeFileSync(`${file}.lock`, '999999:deadbeef', { mode: 0o600 }); // a holder that crashed: no such process
  const started = Date.now();
  await new FileKeystore(file).put(key('first'));
  assert.ok(Date.now() - started < 5000, 'no waiting for a process that is gone');
  // several processes arriving at a dead lock together
  writeFileSync(`${file}.lock`, '999998:deadbeef', { mode: 0o600 });
  const worker = fileURLToPath(new URL('./storage-worker.ts', import.meta.url));
  const results = await Promise.all(Array.from({ length: 6 }, (_, i) => run(worker, [String(i), '10'], { AGENTLOGIN_HOME: home })));
  for (const r of results) assert.equal(r.code, 0, r.stderr);
  assert.equal((await new FileKeystore(file).list()).length, 61);
  assert.equal(existsSync(`${file}.lock`), false);
  assert.equal(existsSync(`${file}.lock.takeover`), false);
});

test('lock: a holder that was taken over neither writes nor removes the new holder\'s lock', async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-lost-'));
  const file = join(home, 'keys.json');
  writePrivateJson(file, [key('kept')]);
  await assert.rejects(
    withFileLock(file, (guard) => {
      // While this holder is inside its critical section, it is taken for dead and another process takes the lock.
      writeFileSync(`${file}.lock`, `${process.pid}:someone-else`);
      writePrivateJson(file, [key('stale-write')], guard);
    }),
    /lost the lock/,
  );
  assert.deepEqual((JSON.parse(readFileSync(file, 'utf8')) as Array<{ kid: string }>).map((k) => k.kid), ['kept'], 'nothing was written');
  assert.equal(readFileSync(`${file}.lock`, 'utf8'), `${process.pid}:someone-else`, 'the new holder\'s lock is still there');
});

test('lock: a live holder that stopped refreshing its lock is taken over after the staleness threshold', async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-stale-'));
  const file = join(home, 'keys.json');
  writeFileSync(`${file}.lock`, `${process.pid}:suspended`, { mode: 0o600 }); // this process is alive, so only age counts
  await assert.rejects(Promise.race([new FileKeystore(file).put(key('early')), new Promise((_, reject) => setTimeout(() => reject(new Error('still waiting')), 600))]), /still waiting/, 'a fresh lock of a live holder is respected');
  const old = new Date(Date.now() - 60_000);
  utimesSync(`${file}.lock`, old, old);
  await new FileKeystore(file).put(key('late'));
  assert.ok((await new FileKeystore(file).list()).some((k) => k.kid === 'late'));
});

test('freshness follows the whole response: Age, Expires and malformed max-age', () => {
  const now = new Date().toUTCString();
  const cases: Array<[Record<string, string>, number]> = [
    [{}, 300],
    [{ 'cache-control': 'max-age=600' }, 600],
    [{ 'cache-control': 'max-age=3600', age: '3600' }, 0],
    [{ 'cache-control': 'max-age=3600', age: '3000' }, 600],
    [{ 'cache-control': 'max-age="0"' }, 0],
    [{ 'cache-control': 'max-age="120"' }, 120],
    [{ 'cache-control': 'max-age=-1' }, 0],
    [{ 'cache-control': 'max-age=abc' }, 0],
    [{ 'cache-control': 'MAX-AGE=0' }, 0],
    [{ 'cache-control': 'max-age=60, no-cache' }, 0],
    [{ 'cache-control': 'private, must-revalidate, max-age=0' }, 0],
    [{ 'cache-control': 'max-age=999999999' }, 86400],
    [{ expires: '0' }, 0],
    [{ expires: 'Thu, 01 Jan 1970 00:00:00 GMT' }, 0],
    [{ expires: now, date: now }, 0],
    [{ expires: new Date(Date.now() + 120_000).toUTCString(), date: now }, 120],
    [{ 'cache-control': 'private', expires: '-1' }, 0],
  ];
  for (const [headers, want] of cases) assert.equal(freshness(headers, 300), want, JSON.stringify(headers));
  assert.equal(freshness({ 'cache-control': ['max-age=600', 'no-store'] }, 300), 0, 'several header lines');
});

test('WebFinger delegation by redirect: the redirect\'s caching terms bound the result', async () => {
  // The delegating host answers with a redirect; its target says "keep this for a day".
  let redirectHeaders: Record<string, string> = {};
  const second = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/jrd+json', 'cache-control': 'max-age=86400' });
    res.end(JSON.stringify({ links: [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: 'https://issuer.example' }] }));
  });
  await new Promise<void>((r) => second.listen(0, '127.0.0.1', r));
  const target = `http://127.0.0.1:${(second.address() as AddressInfo).port}/.well-known/webfinger`;
  const first = http.createServer((_req, res) => { res.writeHead(302, { location: target, ...redirectHeaders }); res.end(); });
  await new Promise<void>((r) => first.listen(0, '127.0.0.1', r));
  const start = `http://127.0.0.1:${(first.address() as AddressInfo).port}/.well-known/webfinger`;
  try {
    for (const [headers, want] of [[{}, 0], [{ 'cache-control': 'no-store' }, 0], [{ 'cache-control': 'max-age=0' }, 0], [{ 'cache-control': 'max-age=30' }, 30]] as Array<[Record<string, string>, number]>) {
      redirectHeaders = headers;
      const res = await safeFetch(start, { maxBytes: 65536, timeoutMs: 5000, allowPrivate: true, maxRedirects: 5 });
      assert.equal(res.status, 200);
      assert.equal(res.redirects.length, 1, 'the redirect hop is reported');
      assert.equal(chainFreshness(res, 300), want, JSON.stringify(headers));
    }
    // without a redirect the target's own terms apply
    assert.equal(chainFreshness(await safeFetch(target, { maxBytes: 65536, timeoutMs: 5000, allowPrivate: true }), 300), 86400);
  } finally {
    await new Promise<void>((r) => second.close(() => r()));
    await new Promise<void>((r) => first.close(() => r()));
  }
});
