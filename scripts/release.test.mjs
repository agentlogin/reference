import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { publishAndVerify, registryVersion, packageFolders, parsePackOutput, preflightPublishedVersion, readRegistryTags, reconcilePublishedVersion, validateDispatchCommit, validateManifests, validatePackedFiles, validateRegistryTags } from './release.mjs';

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
    (p) => { p.version = `${version}.different`; },
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

test('only the seven recorded initial scoped beta.1 publications may retain npm-assigned latest', () => {
  const names = ['issuer', 'conformance', 'agentid-mcp', 'rp', 'mcp', 'store-postgres', 'rp-store-postgres'].map(name => `@agentlogin/${name}`);
  for (const name of names) validateRegistryTags({ name, version: '0.2.0-beta.1' }, { beta: '0.2.0-beta.1', latest: '0.2.0-beta.1' });
  for (const name of ['agentlogin', 'sentfromai-mcp', '@agentlogin/new-package', '@other/issuer']) {
    assert.throws(() => validateRegistryTags({ name, version: '0.2.0-beta.1' }, { beta: '0.2.0-beta.1', latest: '0.2.0-beta.1' }), /must not be the latest/);
  }
  for (const version of ['0.2.0-beta.2', '0.3.0-beta.1']) {
    assert.throws(() => validateRegistryTags({ name: names[0], version }, { beta: version, latest: version }), /must not be the latest/);
  }
});

test('the initial-publication exception still requires the exact beta tag and immutable bytes', async () => {
  const p = { name: '@agentlogin/issuer', version: '0.2.0-beta.1', integrity: 'sha512-tested' };
  for (const tags of [null, {}, { latest: p.version }, { beta: '0.2.0-beta.2', latest: p.version }]) {
    assert.throws(() => validateRegistryTags(p, tags));
  }
  await assert.rejects(reconcilePublishedVersion(p, async () => ({ dist: { integrity: 'sha512-different' } }), () => validateRegistryTags(p, { beta: p.version, latest: p.version })), /different bytes/);
});

test('an existing latest default cannot be replaced or removed, even for an initial scoped package', () => {
  for (const name of ['agentlogin', '@agentlogin/issuer']) {
    const p = { name, version: '0.2.0-beta.1' };
    validateRegistryTags(p, { beta: p.version, latest: '0.0.0' }, '0.0.0');
    for (const latest of [undefined, '0.1.0', p.version]) {
      assert.throws(() => validateRegistryTags(p, { beta: p.version, latest }, '0.0.0'));
    }
  }
});

test('registry tags are read directly, without relying on package-wide index visibility', async () => {
  const p = { name: '@agentlogin/issuer' };
  const tags = { beta: '0.2.0-beta.1', latest: '0.2.0-beta.1' };
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push(url); assert.equal(options.redirect, 'error');
    return Response.json(tags);
  };
  assert.deepEqual(await readRegistryTags(p, fetcher), tags);
  assert.deepEqual(calls, ['https://registry.npmjs.org/-/package/%40agentlogin%2Fissuer/dist-tags']);
  await assert.rejects(readRegistryTags(p, async () => new Response(null, { status: 503 })), /Cannot read dist-tags/);
});

test('malformed successful tag responses cannot be mistaken for absent publication', async () => {
  const p = { name: '@agentlogin/issuer', version: '0.2.0-beta.1' };
  for (const malformed of [null, [], 42, 'not a tag map', { latest: null }, { beta: 1 }, { latest: '' }]) {
    const lookupTags = () => readRegistryTags(p, async () => Response.json(malformed));
    await assert.rejects(preflightPublishedVersion(p, async () => null, lookupTags), /Cannot read dist-tags/);
  }
  assert.equal(await readRegistryTags(p, async () => new Response(null, { status: 404 })), null);
});

test('partially visible publication fails preflight instead of being treated as absent', async () => {
  const p = { name: '@agentlogin/issuer', version: '0.2.0-beta.1', integrity: 'sha512-tested' };
  for (const tags of [{ beta: p.version }, { latest: p.version }]) {
    await assert.rejects(preflightPublishedVersion(p, async () => null, async () => tags), /pending registry visibility/);
  }
  await assert.rejects(preflightPublishedVersion(p, async () => ({ dist: { integrity: p.integrity } }), async () => null), /Cannot read dist-tags/);
  assert.deepEqual(await preflightPublishedVersion(p, async () => null, async () => null), { exists: false, latest: undefined });
  assert.deepEqual(await preflightPublishedVersion(p, async () => null, async () => ({ beta: '0.1.0-beta.1', latest: '0.0.0' })), { exists: false, latest: '0.0.0' });
});


const pendingPackage = {name: 'synthetic-package', version: '0.9.0-beta.2', integrity: 'sha512-reviewed'};
const pendingBaseline = {beta: '0.9.0-beta.1', latest: '0.8.0'};
const visibleVersion = {dist: {integrity: pendingPackage.integrity}};
const visibleTags = {...pendingBaseline, beta: pendingPackage.version};
function fakeReadback({versions = [], tags = [], timeoutMs = 300_000, pollIntervalMs = 10_000} = {}) {
  let clock = 0, uploads = 0, versionReads = 0, tagReads = 0;
  const waits = [];
  return {
    upload: async () => { uploads++; },
    options: {timeoutMs, pollIntervalMs, now: () => clock,
      sleep: async ms => { waits.push(ms); clock += ms; },
      lookup: async () => versions[Math.min(versionReads++, versions.length - 1)],
      lookupTags: async () => tags[Math.min(tagReads++, tags.length - 1)]},
    counts: () => ({clock, uploads, versionReads, tagReads, waits}),
  };
}

test('accepted upload waits for independent version/tag visibility without uploading again', async () => {
  const f = fakeReadback({versions: [null, null, visibleVersion], tags: [pendingBaseline, visibleTags, visibleTags]});
  assert.equal(await publishAndVerify(pendingPackage, pendingBaseline, f.upload, f.options), true);
  assert.deepEqual(f.counts(), {clock: 20_000, uploads: 1, versionReads: 3, tagReads: 3, waits: [10_000, 10_000]});
});

test('visible bytes can wait for the exact old beta or absent tag endpoint, never replace latest', async () => {
  const f = fakeReadback({versions: [visibleVersion], tags: [null, pendingBaseline, visibleTags]});
  assert.equal(await publishAndVerify(pendingPackage, pendingBaseline, f.upload, f.options), true);
  assert.equal(f.counts().uploads, 1);
  assert.equal(f.counts().clock, 20_000);
  const first = fakeReadback({versions: [null, visibleVersion], tags: [null, {beta: pendingPackage.version}]});
  assert.equal(await publishAndVerify(pendingPackage, null, first.upload, first.options), true);
});

test('metadata conflicts and unexpected tag changes fail on their first observation even during 404', async () => {
  for (const [versions, tags, pattern] of [
    [[{dist:{integrity:'sha512-other'}}], [visibleTags], /different bytes/],
    [[null], [{...pendingBaseline, beta:'0.9.0-beta.3'}], /beta dist-tag changed/],
    [[null], [{...pendingBaseline, latest:'0.8.1'}], /latest dist-tag changed/],
    [[null], [{beta:pendingBaseline.beta}], /latest dist-tag changed/],
    [[visibleVersion], [{...visibleTags, latest:pendingPackage.version}], /latest dist-tag changed/],
  ]) {
    const f = fakeReadback({versions, tags});
    await assert.rejects(publishAndVerify(pendingPackage, pendingBaseline, f.upload, f.options), pattern);
    assert.equal(f.counts().uploads, 1); assert.deepEqual(f.counts().waits, []);
  }
  const absentLatest = fakeReadback({versions:[null], tags:[{beta:pendingPackage.version,latest:'0.8.0'}]});
  await assert.rejects(publishAndVerify(pendingPackage, null, absentLatest.upload, absentLatest.options), /latest dist-tag changed/);
});

test('observed expected beta cannot roll back to its previous value while metadata is pending', async () => {
  const f = fakeReadback({versions:[null], tags:[visibleTags,pendingBaseline]});
  await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,f.upload,f.options), /beta dist-tag changed/);
  assert.deepEqual(f.counts().waits,[10_000]); assert.equal(f.counts().uploads,1);
});

test('five-minute visibility limit stops unresolved with one upload and no extra read', async () => {
  const f = fakeReadback({versions:[null],tags:[pendingBaseline]});
  await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,f.upload,f.options), /remains unresolved.*reconcile/);
  const result=f.counts();
  assert.equal(result.clock,300_000); assert.equal(result.uploads,1);
  assert.equal(result.versionReads,30); assert.equal(result.tagReads,30);
  assert.equal(result.waits.length,30);
});

test('failed upload and unknown read errors never trigger replay or success', async () => {
  const f = fakeReadback({versions:[visibleVersion],tags:[visibleTags]});
  await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,async()=>{throw new Error('upload outcome unknown');},f.options), /upload outcome unknown/);
  assert.equal(f.counts().versionReads,0);
  for (const field of ['lookup','lookupTags']) {
    const f = fakeReadback({versions:[visibleVersion],tags:[visibleTags]});
    f.options[field]=async()=>{throw new Error('network outcome unknown');};
    await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,f.upload,f.options), /network outcome unknown/);
    assert.equal(f.counts().uploads,1); assert.deepEqual(f.counts().waits,[]);
  }
  for (const tags of [undefined,[],42,{beta:7}]) {
    const f=fakeReadback({versions:[visibleVersion],tags:[tags]});
    await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,f.upload,f.options),/Cannot read dist-tags/);
    assert.deepEqual(f.counts().waits,[]);
  }
});

test('read timeout budget and final expiry include time spent reading metadata bodies', async t => {
  let now=0; const limits=[];
  t.mock.method(AbortSignal,'timeout',ms=>{limits.push(ms);return new AbortController().signal;});
  await assert.rejects(publishAndVerify(pendingPackage,pendingBaseline,async()=>{now=5_000;},{
    timeoutMs:100,now:()=>now,sleep:async()=>assert.fail('must not sleep after expiry'),
    lookup:async()=>{now+=40;return visibleVersion;},
    lookupTags:async()=>{now+=60;return visibleTags;},
  }),/remains unresolved/);
  assert.deepEqual(limits,[100,60]);
});


test('successful malformed version responses are unknown, not absent publications', async () => {
  for (const value of [null, [], false, 42, 'missing']) await assert.rejects(registryVersion(pendingPackage,async()=>Response.json(value)),/Cannot check registry state/);
  assert.equal(await registryVersion(pendingPackage,async()=>new Response(null,{status:404})),null);
});
