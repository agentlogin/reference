// Regression tests for the client's local storage and discovery (reported against commit 9b6dd09).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FileCookieJar, FileKeystore, acctUri, fetchMetadata, parseHandle, webfingerUrl } from '../src/index.js';

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
