import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { packageFolders, parsePackOutput, reconcilePublishedVersion, validateDispatchCommit, validateManifests, validatePackedFiles } from './release.mjs';

const manifests = () => packageFolders.map((folder) => JSON.parse(readFileSync(new URL(`../packages/${folder}/package.json`, import.meta.url))));
const version = manifests()[0].version;

test('single-package pack metadata accepts npm 10/11 and npm 12, rejecting extra packages', () => {
  const packed = { name: 'agentlogin', filename: 'agentlogin-0.2.0-beta.1.tgz', integrity: 'sha512-dGVzdA==' };
  assert.deepEqual(parsePackOutput(JSON.stringify([packed]), packed.name), packed);
  assert.deepEqual(parsePackOutput(JSON.stringify({ [packed.name]: packed }), packed.name), packed);
  assert.throws(() => parsePackOutput(JSON.stringify([packed, packed]), packed.name));
  assert.throws(() => parsePackOutput(JSON.stringify({ error: { code: 'E404' } }), packed.name));
  assert.throws(() => parsePackOutput(JSON.stringify([{ ...packed, filename: '../outside.tgz' }]), packed.name));
});

test('release graph is one beta with exact internal versions in publication order', () => {
  validateManifests(manifests(), version);
});

test('release refuses stable versions, latest, private registry and mismatched source repository', () => {
  assert.throws(() => validateManifests(manifests(), '0.2.0'), /beta/);
  for (const mutate of [
    (p) => { p.publishConfig.tag = 'latest'; },
    (p) => { p.publishConfig.registry = 'https://registry.example/'; },
    (p) => { p.repository.url = 'git+https://github.com/other/reference.git'; },
    (p) => { p.version = '0.2.0-beta.2'; },
  ]) {
    const packages = manifests(); mutate(packages[0]);
    assert.throws(() => validateManifests(packages, version));
  }
});

test('release refuses version drift and local dependencies which workspace links can conceal', () => {
  for (const target of ['file:../agentlogin', 'workspace:*', '^0.2.0-beta.1', '0.1.0']) {
    const packages = manifests(); packages.find((p) => p.name === '@agentlogin/rp').dependencies.agentlogin = target;
    assert.throws(() => validateManifests(packages, version));
  }
});

test('artifact allowlist excludes secrets, source, tests, hidden files and path traversal', () => {
  const p = manifests()[0];
  const base = ['package.json', 'README.md', 'LICENSE', p.main, p.types, ...Object.values(p.bin)];
  validatePackedFiles(base, p);
  for (const path of ['.env', '.npmrc', 'private-key.pem', 'state/key.json', 'src/index.ts', 'test/fixture.json', '../private.json', '/absolute.json', 'dist/../secrets.js', 'dist/.secret.js', 'dist/token.json']) {
    assert.throws(() => validatePackedFiles([...base, path], p), undefined, path);
  }
});

test('artifact allowlist requires license and executable entrypoints', () => {
  const p = manifests()[0];
  const base = ['package.json', 'README.md', 'LICENSE', p.main, p.types, ...Object.values(p.bin)];
  for (const entry of ['LICENSE', p.main, ...Object.values(p.bin)]) assert.throws(() => validatePackedFiles(base.filter((name) => name !== entry), p));
});

test('only reviewed plugin examples and skills may enter their corresponding packages', () => {
  const p = manifests().find((p) => p.name === '@agentlogin/mcp');
  const base = ['package.json', 'README.md', 'LICENSE', p.main, p.types, ...Object.values(p.bin)];
  validatePackedFiles([...base, 'skills/agent-login/SKILL.md', 'examples/config.json'], p);
  assert.throws(() => validatePackedFiles([...base, 'examples/actual-owner-config.json'], p));
  assert.throws(() => validatePackedFiles([...base, 'skills/agentid-sign-in/SKILL.md'], p));
});

test('provenance source is the actual workflow commit, not an older reachable commit', () => {
  const head = 'a'.repeat(40);
  validateDispatchCommit(head, head);
  assert.throws(() => validateDispatchCommit('b'.repeat(40), head), /dispatch commit/);
  assert.throws(() => validateDispatchCommit(head, undefined));
});

test('a version appearing after preflight must still match the tested bytes', async () => {
  const p = { name: 'agentlogin', version, integrity: 'sha512-tested' };
  let reads = 0; let tagChecks = 0;
  const lookup = async () => ++reads === 1 ? null : { dist: { integrity: 'sha512-different' } };
  const tags = async () => { tagChecks++; };
  assert.equal(await reconcilePublishedVersion(p, lookup, tags), false);
  await assert.rejects(reconcilePublishedVersion(p, lookup, tags), /different bytes/);
  assert.equal(tagChecks, 0);
});

test('resume requires both matching artifact bytes and the intended beta tag on every read', async () => {
  const p = { name: 'agentlogin', version, integrity: 'sha512-tested' };
  const lookup = async () => ({ dist: { integrity: p.integrity } });
  let checks = 0;
  const tags = async () => { checks++; if (checks > 1) throw new Error('beta tag changed'); };
  assert.equal(await reconcilePublishedVersion(p, lookup, tags), true);
  await assert.rejects(reconcilePublishedVersion(p, lookup, tags), /tag changed/);
});
