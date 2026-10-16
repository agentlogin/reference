// Regression tests for the client's local storage and discovery (reported against commit 9b6dd09).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import { existsSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
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

test('lock: publication closes its descriptor only once, including when linking fails', async (t) => {
  for (const failLink of [false, true]) await t.test(failLink ? 'failed link' : 'successful link', async (t) => {
    const home = mkdtempSync(join(tmpdir(), 'al-lock-fd-'));
    const file = join(home, 'keys.json');
    const originalOpen = fs.openSync;
    const originalLink = fs.linkSync;
    let ownerFd: number | undefined;
    let unrelatedFd: number | undefined;
    const failure = new Error('link failed');
    t.mock.method(fs, 'openSync', (...args: Parameters<typeof fs.openSync>) => {
      const fd = originalOpen(...args);
      if (String(args[0]).endsWith('.owner')) ownerFd = fd;
      return fd;
    });
    t.mock.method(fs, 'linkSync', (...args: Parameters<typeof fs.linkSync>) => {
      // Reuse the just-closed owner's fd in the gap before publication's cleanup.
      unrelatedFd = originalOpen(join(home, 'unrelated'), 'wx', 0o600);
      assert.equal(unrelatedFd, ownerFd, 'the unrelated file reuses the closed descriptor');
      if (failLink) throw failure;
      return originalLink(...args);
    });
    syncBuiltinESMExports();
    try {
      const write = new FileKeystore(file).put(key('kept'));
      if (failLink) await assert.rejects(write, (error) => error === failure);
      else await write;
      assert.notEqual(unrelatedFd, undefined, 'the publication hook ran');
      fs.writeSync(unrelatedFd!, 'still open');
      assert.equal(readFileSync(join(home, 'unrelated'), 'utf8'), 'still open');
      assert.equal(fs.readdirSync(home).some((name) => name.endsWith('.owner')), false, 'the candidate is removed');
      assert.equal(existsSync(`${file}.lock`), false, 'the lock is released');
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
      if (unrelatedFd !== undefined) try { fs.closeSync(unrelatedFd); } catch { /* regression may have closed it */ }
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

test('private write: a rejecting guard cannot close a reused descriptor', () => {
  const home = mkdtempSync(join(tmpdir(), 'al-guard-fd-'));
  const file = join(home, 'keys.json');
  let unrelatedFd: number | undefined;
  const failure = new Error('guard rejected the write');
  try {
    writePrivateJson(file, [key('kept')]);
    assert.throws(() => writePrivateJson(file, [key('discarded')], () => {
      // The temporary file is closed before the guard; the next open reuses its fd.
      unrelatedFd = fs.openSync(join(home, 'unrelated'), 'wx', 0o600);
      throw failure;
    }), (error) => error === failure);
    fs.writeSync(unrelatedFd!, 'still open');
    assert.equal(readFileSync(join(home, 'unrelated'), 'utf8'), 'still open');
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), [key('kept')]);
    assert.equal(fs.readdirSync(home).some((name) => name.endsWith('.tmp')), false, 'the temporary write is removed');
  } finally {
    if (unrelatedFd !== undefined) try { fs.closeSync(unrelatedFd); } catch { /* regression may have closed it */ }
    fs.rmSync(home, { recursive: true, force: true });
  }
});

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

test('lock: externally changed ownership fails closed before writing', async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-lost-'));
  const file = join(home, 'keys.json');
  writePrivateJson(file, [key('kept')]);
  await assert.rejects(
    withFileLock(file, (guard) => {
      // Defense in depth: detect unsupported external replacement before writing.
      writeFileSync(`${file}.lock`, `${process.pid}:someone-else`);
      writePrivateJson(file, [key('stale-write')], guard);
    }),
    /lost the lock/,
  );
  assert.deepEqual((JSON.parse(readFileSync(file, 'utf8')) as Array<{ kid: string }>).map((k) => k.kid), ['kept'], 'nothing was written');
  assert.equal(readFileSync(`${file}.lock`, 'utf8'), `${process.pid}:someone-else`, 'the new holder\'s lock is still there');
});

test('lock: a writer suspended after its ownership check cannot be evicted before rename', { skip: process.platform === 'win32', timeout: 10_000 }, async () => {
  const home = mkdtempSync(join(tmpdir(), 'al-suspended-'));
  const file = join(home, 'keys.json');
  const marker = join(home, 'checked');
  writePrivateJson(file, [key('initial')]);
  const worker = fileURLToPath(new URL('./suspended-writer.ts', import.meta.url));
  const child = spawn(process.execPath, ['--import', 'tsx', worker, file, marker], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const exited = new Promise<number | null>((resolve) => child.once('exit', resolve));
  try {
    const until = Date.now() + 5000;
    while (!existsSync(marker) && child.exitCode === null && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
    assert.ok(existsSync(marker), `writer reached the check/rename gap: ${stderr}`);
    const old = new Date(Date.now() - 60_000);
    utimesSync(`${file}.lock`, old, old); // the old lease algorithm would evict this still-live writer
    let finished = false;
    const second = new FileKeystore(file).put(key('second')).then(() => { finished = true; });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(finished, false, 'no writer may pass a suspended live owner, even after the old stale threshold');
    child.kill('SIGCONT');
    assert.equal(await exited, 0, stderr);
    await second;
    assert.deepEqual((await new FileKeystore(file).list()).map((k) => k.kid).sort(), ['first', 'initial', 'second']);
  } finally {
    child.kill('SIGKILL');
    await exited;
  }
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
