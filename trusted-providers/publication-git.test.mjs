import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compilePublication, encode } from './publisher.mjs';
import { fixture, administrativeDecision, previousFeed } from './publication-fixtures.mjs';
import { git, ref, show, publicationBase, stageArtifact, readArtifact, createPublicationCommit, pushPublication, SITE_FILES, FEED_PATH, STATE_PATH, sha256 } from './publication-git.mjs';
import { prepare, publish, verifyLive } from './publish.mjs';

function repository() {
  const root = mkdtempSync(join(tmpdir(), 'agentlogin-policy-git-test-'));
  const remote = join(root, 'remote.git'), local = join(root, 'source');
  mkdirSync(remote); git(remote, ['init', '--bare', '--quiet']);
  mkdirSync(local); git(local, ['init', '--quiet', '-b', 'main']);
  git(local, ['config', 'user.name', 'Synthetic publisher test']); git(local, ['config', 'user.email', 'synthetic@example.invalid']);
  mkdirSync(join(local, 'trusted-providers')); writeFileSync(join(local, FEED_PATH), previousFeed);
  writeFileSync(join(local, 'README.md'), 'Synthetic test repository'); git(local, ['add', '.']); git(local, ['commit', '--quiet', '-m', 'Initial fixture']);
  const initial = ref(local, 'HEAD'); git(local, ['branch', 'gh-pages']); git(local, ['remote', 'add', 'origin', remote]);
  git(local, ['push', '--quiet', 'origin', 'main', 'gh-pages']);
  return { root, remote, local, initial, close() { rmSync(root, { recursive: true, force: true }); } };
}
function site(publication) {
  const files = Object.fromEntries(SITE_FILES.map((path) => [path, Buffer.from(`Synthetic ${path}\n`)]));
  files['.nojekyll'] = Buffer.alloc(0); files[FEED_PATH] = publication.body;
  files[STATE_PATH] = encode(publication.state); files['trusted-providers/index.html'] = Buffer.from(publication.html);
  return files;
}
async function initialPublication(repo) {
  const input = fixture(); input.pagesCommit = repo.initial; input.sourceCommit = repo.initial; input.adoption.publication.bootstrapCommit = repo.initial;
  const publication = await compilePublication(input); return { input, publication, files: site(publication) };
}
function fetch(repo) { git(repo.local, ['fetch', '--tags', 'origin', 'main:refs/remotes/origin/main', 'gh-pages:refs/remotes/origin/gh-pages']); }
function commit(repo, publication, files, parent = repo.initial, name = 'index') {
  return createPublicationCommit(repo.local, parent, files, publication.state.revision, join(repo.root, name));
}

test('one non-force atomic push records the whole site and recovery anchor', async () => {
  const repo = repository();
  try {
    const { publication, files } = await initialPublication(repo);
    const commitId = commit(repo, publication, files); pushPublication(repo.local, commitId, 2); fetch(repo);
    assert.equal(ref(repo.local, 'origin/gh-pages'), commitId);
    assert.equal(ref(repo.local, 'provider-policy-r2'), commitId);
    const base = publicationBase(repo.local, commitId, repo.initial);
    assert.equal(base.previous.revision, 2); assert.equal(base.anchor.commit, commitId);
    for (const path of SITE_FILES) assert.deepEqual(show(repo.local, commitId, path), files[path]);
    assert.equal(git(repo.local, ['status', '--porcelain']), '', 'private Git index preserves source checkout');
  } finally { repo.close(); }
});

test('competing publishers cannot overwrite the winner or leave a partial anchor', async () => {
  const repo = repository();
  try {
    const { publication, files } = await initialPublication(repo);
    const winner = commit(repo, publication, files, repo.initial, 'index-winner');
    const alternate = { ...files, 'index.html': Buffer.from('Other prepared catalog') };
    const loser = commit(repo, publication, alternate, repo.initial, 'index-loser');
    pushPublication(repo.local, winner, 2);
    assert.throws(() => pushPublication(repo.local, loser, 2));
    assert.equal(ref(repo.remote, 'refs/heads/gh-pages'), winner);
    assert.equal(ref(repo.remote, 'refs/tags/provider-policy-r2'), winner);
    // A new tag cannot partly succeed when the branch update loses its compare-and-swap.
    assert.throws(() => pushPublication(repo.local, loser, 3));
    assert.throws(() => ref(repo.remote, 'refs/tags/provider-policy-r3'));
  } finally { repo.close(); }
});

test('old restored Pages and source trees cannot revive a suspended provider', async () => {
  const repo = repository();
  try {
    const first = await initialPublication(repo);
    const c2 = commit(repo, first.publication, first.files); pushPublication(repo.local, c2, 2); fetch(repo);
    writeFileSync(join(repo.local, 'README.md'), 'Source now contains suspension'); git(repo.local, ['add', '.']); git(repo.local, ['commit', '--quiet', '-m', 'Suspend fixture']);
    const source2 = ref(repo.local, 'HEAD');
    const input = { ...first.input, sourceCommit: source2, pagesCommit: c2, previous: first.publication.state, previousFeed: first.publication.body, now: first.input.now + 60000 };
    input.decisions.decisions.push(administrativeDecision(input.decisions.decisions[0]));
    const suspended = await compilePublication(input), c3 = commit(repo, suspended, site(suspended), c2, 'index-suspend');
    pushPublication(repo.local, c3, 3); fetch(repo);
    assert.deepEqual(JSON.parse(show(repo.local, c3, FEED_PATH)).providers, []);
    assert.throws(() => publicationBase(repo.local, c2, source2), /restored behind/);
    assert.throws(() => publicationBase(repo.local, c3, repo.initial), /source history was restored/);
    const base = publicationBase(repo.local, c3, source2);
    const restored = { ...input, ...base, pagesCommit: c3, now: input.now + 60000, decisions: { version: 1, decisions: [input.decisions.decisions[0]] } };
    await assert.rejects(compilePublication(restored), /decision history changed/);
  } finally { repo.close(); }
});

test('missing anchors, anchor gaps and edits outside the publisher are refused', async () => {
  const repo = repository();
  try {
    const { publication, files } = await initialPublication(repo);
    const c2 = commit(repo, publication, files); // Commit without immutable tag is not a complete release.
    assert.throws(() => publicationBase(repo.local, c2, repo.initial), /lost its release anchor/);
    pushPublication(repo.local, c2, 2); fetch(repo);
    const tampered = { ...files, [FEED_PATH]: Buffer.from('{}') };
    const changed = commit(repo, publication, tampered, c2, 'index-change');
    assert.throws(() => publicationBase(repo.local, changed, repo.initial), /outside the anchored/);
    git(repo.local, ['tag', 'provider-policy-r4', c2]);
    assert.throws(() => publicationBase(repo.local, c2, repo.initial), /history is incomplete/);
  } finally { repo.close(); }
});

test('staged artifacts detect tamper, omitted files, added files and symbolic links', async () => {
  const root = mkdtempSync(join(tmpdir(), 'agentlogin-policy-artifact-'));
  try {
    const p = await compilePublication(fixture()), files = site(p);
    const a = join(root, 'a'); const digest = stageArtifact(a, files, { revision: 2 });
    assert.deepEqual(readArtifact(a, digest).files[FEED_PATH], p.body);
    writeFileSync(join(a, 'site', FEED_PATH), '{}'); assert.throws(() => readArtifact(a, digest), /artifact changed/);
    writeFileSync(join(a, 'site', FEED_PATH), p.body); rmSync(join(a, 'site', 'LICENSE')); assert.throws(() => readArtifact(a, digest), /incomplete/);
    symlinkSync(join(a, 'site', FEED_PATH), join(a, 'site', 'LICENSE')); assert.throws(() => readArtifact(a, digest), /non-regular/);
    const b = join(root, 'b'); const digest2 = stageArtifact(b, files, { revision: 2 });
    writeFileSync(join(b, 'site', 'extra.html'), 'extra'); assert.throws(() => readArtifact(b, digest2), /incomplete/);
    const c = join(root, 'c'); const digest3 = stageArtifact(c, files, { revision: 2 });
    writeFileSync(join(c, 'manifest.json'), '{}'); assert.throws(() => readArtifact(c, digest3), /manifest changed/);
    assert.throws(() => stageArtifact(a, files, {}), /must be new/);
    const incomplete = { ...files }; delete incomplete.LICENSE;
    assert.throws(() => stageArtifact(join(root, 'd'), incomplete, {}), /incomplete/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('live verification refuses partial deployments, redirects, expiry and oversized bodies', async () => {
  const root = mkdtempSync(join(tmpdir(), 'agentlogin-policy-live-test-'));
  try {
    const input = fixture(), publication = await compilePublication(input), files = site(publication);
    const a = join(root, 'artifact'), digest = stageArtifact(a, files, { revision: 2, expiresAt: publication.state.expiresAt });
    function fetcher(change = {}) { return async (url, options) => {
      assert.equal(options.redirect, 'error'); assert.equal(options.headers['Cache-Control'], 'no-cache');
      const path = new URL(url).pathname.replace(/^\/reference\//, ''); assert.ok(files[path]);
      const response = new Response(change.bytes ?? files[path], { status: change.status ?? 200 });
      Object.defineProperty(response, 'url', { value: change.url ?? url });
      return response;
    }; }
    await verifyLive(a, digest, fetcher(), input.now);
    let current = input.now;
    const delayed = async (...args) => { current = Date.parse(publication.state.expiresAt); return fetcher()(...args); };
    await assert.rejects(verifyLive(a, digest, delayed, () => current), { code: 'issuer_policy_unavailable' });
    await assert.rejects(verifyLive(a, digest, fetcher({ bytes: Buffer.from('old feed') }), input.now), /incomplete/);
    await assert.rejects(verifyLive(a, digest, fetcher({ url: 'https://other.example/' }), input.now), /response is invalid/);
    await assert.rejects(verifyLive(a, digest, fetcher({ status: 503 }), input.now), /response is invalid/);
    await assert.rejects(verifyLive(a, digest, fetcher({ bytes: Buffer.alloc(2 * 1024 * 1024 + 1) }), input.now), /too large/);
    await assert.rejects(verifyLive(a, digest, fetcher(), Date.parse(publication.state.expiresAt)), /expired/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('the complete staged publisher reconciles retries without reissuing and rejects source drift', async () => {
  const repo = repository();
  const priorEnv = { repository: process.env.GITHUB_REPOSITORY, ref: process.env.GITHUB_REF, sha: process.env.GITHUB_SHA, output: process.env.GITHUB_OUTPUT, path: process.env.PATH };
  const realNow = Date.now;
  try {
    const input = fixture(); input.adoption.publication.bootstrapCommit = repo.initial;
    Date.now = () => input.now;
    process.env.GITHUB_REPOSITORY = 'agentlogin/reference'; process.env.GITHUB_REF = 'refs/heads/main';
    process.env.GITHUB_OUTPUT = join(repo.root, 'outputs');
    // Stub only the canonical URL guard; every fetch, commit and atomic push uses real local Git.
    mkdirSync(join(repo.root, 'bin'));
    const gitShim = join(repo.root, 'bin/git');
    writeFileSync(gitShim, '#!/bin/sh\nif [ \"$1\" = remote ] && [ \"$2\" = get-url ] && [ \"$3\" = origin ]; then\n  echo https://github.com/agentlogin/reference\nelse\n  exec /usr/bin/git \"$@\"\nfi\n');
    chmodSync(gitShim, 0o700); process.env.PATH = `${join(repo.root, 'bin')}:${process.env.PATH}`;
    git(repo.local, ['config', `url.${repo.remote}.insteadOf`, 'https://github.com/agentlogin/reference']);
    git(repo.local, ['remote', 'set-url', 'origin', 'https://github.com/agentlogin/reference']);
    mkdirSync(join(repo.local, 'catalogs/dist'), { recursive: true });
    for (const path of ['applications.json', 'catalog.schema.json', 'index.html', 'providers.json']) writeFileSync(join(repo.local, 'catalogs/dist', path), 'synthetic public site');
    writeFileSync(join(repo.local, 'LICENSE'), 'Synthetic fixture license');
    writeFileSync(join(repo.local, 'trusted-providers/adoption.json'), encode(input.adoption));
    writeFileSync(join(repo.local, 'trusted-providers/decisions.json'), encode(input.decisions));
    git(repo.local, ['add', '.']); git(repo.local, ['commit', '--quiet', '-m', 'Adopt synthetic programme']);
    git(repo.local, ['push', '--quiet', 'origin', 'main']); process.env.GITHUB_SHA = ref(repo.local, 'HEAD');
    const directory = join(repo.root, 'prepared');
    await prepare(repo.local, directory);
    const expectedDigest = sha256(readFileSync(join(directory, 'manifest.json')));
    const first = await publish(repo.local, directory, expectedDigest);
    assert.equal(ref(repo.remote, 'refs/heads/gh-pages'), first);
    const retry = await publish(repo.local, directory, expectedDigest);
    assert.equal(retry, first);
    assert.equal(git(repo.remote, ['tag', '--list', 'provider-policy-r*']).trim(), 'provider-policy-r2');
    const second = join(repo.root, 'prepared-next'); Date.now = () => input.now + 60000;
    await prepare(repo.local, second);
    writeFileSync(join(repo.local, 'README.md'), 'Source changed after preparation');
    git(repo.local, ['add', '.']); git(repo.local, ['commit', '--quiet', '-m', 'New decision source']);
    git(repo.local, ['push', '--quiet', 'origin', 'main']);
    await assert.rejects(publish(repo.local, second, sha256(readFileSync(join(second, 'manifest.json')))), /no longer current main/);
    assert.equal(ref(repo.remote, 'refs/heads/gh-pages'), first);
    // Simulate restored Pages with a surviving newer immutable recovery anchor.
    process.env.GITHUB_SHA = ref(repo.local, 'HEAD');
    const secondDigest = sha256(readFileSync(join(second, 'manifest.json')));
    const newer = createPublicationCommit(repo.local, first, readArtifact(second, secondDigest).files, 3, join(repo.root, 'newer-index'));
    git(repo.local, ['push', '--quiet', 'origin', `${newer}:refs/tags/provider-policy-r3`]);
    await assert.rejects(publish(repo.local, directory, expectedDigest), /restored behind the latest publication anchor/);
  } finally {
    Date.now = realNow;
    for (const [key, value] of [['GITHUB_REPOSITORY', priorEnv.repository], ['GITHUB_REF', priorEnv.ref], ['GITHUB_SHA', priorEnv.sha], ['GITHUB_OUTPUT', priorEnv.output], ['PATH', priorEnv.path]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    repo.close();
  }
});

test('a source suspension arriving during atomic push prevents success and recovers through a higher release', async () => {
  const repo = repository();
  const saved = Object.fromEntries(['PATH', 'GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_OUTPUT'].map((key) => [key, process.env[key]]));
  const realNow = Date.now;
  try {
    const input = fixture(); input.adoption.publication.bootstrapCommit = repo.initial;
    Date.now = () => input.now + 60000;
    mkdirSync(join(repo.local, 'catalogs/dist'), { recursive: true });
    for (const path of ['applications.json', 'catalog.schema.json', 'index.html', 'providers.json']) writeFileSync(join(repo.local, 'catalogs/dist', path), 'synthetic public site');
    writeFileSync(join(repo.local, 'LICENSE'), 'Synthetic fixture license');
    writeFileSync(join(repo.local, 'trusted-providers/adoption.json'), encode(input.adoption));
    writeFileSync(join(repo.local, 'trusted-providers/decisions.json'), encode(input.decisions));
    git(repo.local, ['add', '.']); git(repo.local, ['commit', '--quiet', '-m', 'Admit fixture before racing publication']);
    const originalSource = ref(repo.local, 'HEAD'); git(repo.local, ['push', '--quiet', 'origin', 'main']);
    input.decisions.decisions.push(administrativeDecision(input.decisions.decisions[0]));
    writeFileSync(join(repo.local, 'trusted-providers/decisions.json'), encode(input.decisions));
    git(repo.local, ['add', '.']); git(repo.local, ['commit', '--quiet', '-m', 'Suspend while publisher is in flight']);
    const newSource = ref(repo.local, 'HEAD');
    // Transfer the source object without making it main until the publisher reaches push.
    git(repo.local, ['push', '--quiet', 'origin', `${newSource}:refs/heads/staged-suspension`]);
    git(repo.local, ['checkout', '--quiet', '--detach', originalSource]);
    git(repo.local, ['remote', 'set-url', 'origin', 'https://github.com/agentlogin/reference']);
    const bin = join(repo.root, 'bin'); mkdirSync(bin);
    const marker = join(repo.root, 'advance-main-once'); writeFileSync(marker, 'synthetic scheduling barrier');
    const readbackFailure = join(repo.root, 'fail-readback-once');
    // Adapted from the independent review probe: canonical URL guard stays real;
    // only transport is local, and the barrier changes main immediately before atomic push.
    const wrapper = `#!${process.execPath}\nimport { spawnSync, execFileSync } from 'node:child_process';\nimport { existsSync, unlinkSync } from 'node:fs';\nconst args = process.argv.slice(2);\nif (args[0] === 'push' && args.includes('--atomic') && existsSync(${JSON.stringify(marker)})) { execFileSync('/usr/bin/git', ['update-ref', 'refs/heads/main', ${JSON.stringify(newSource)}, ${JSON.stringify(originalSource)}], { cwd: ${JSON.stringify(repo.remote)}, stdio: 'pipe' }); unlinkSync(${JSON.stringify(marker)}); }\nif (args[0] === 'ls-remote' && existsSync(${JSON.stringify(readbackFailure)})) { unlinkSync(${JSON.stringify(readbackFailure)}); process.exit(2); }\nif (['fetch', 'push', 'ls-remote'].includes(args[0])) for (let i = 0; i < args.length; i++) if (args[i] === 'origin') args[i] = ${JSON.stringify(repo.remote)};\nconst result = spawnSync('/usr/bin/git', args, { cwd: process.cwd(), env: process.env, stdio: 'inherit' }); process.exit(result.status ?? 1);\n`;
    writeFileSync(join(bin, 'git'), wrapper); chmodSync(join(bin, 'git'), 0o700);
    Object.assign(process.env, { PATH: `${bin}:${saved.PATH}`, GITHUB_REPOSITORY: 'agentlogin/reference', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: originalSource, GITHUB_OUTPUT: join(repo.root, 'outputs') });
    const artifact = join(repo.root, 'racing-artifact'); await prepare(repo.local, artifact);
    const artifactDigest = sha256(readFileSync(join(artifact, 'manifest.json')));
    writeFileSync(process.env.GITHUB_OUTPUT, '');
    await assert.rejects(publish(repo.local, artifact, artifactDigest), /source changed after the validated snapshot.*Do not request a Pages build.*superseding higher revision/);
    assert.equal(ref(repo.remote, 'refs/heads/main'), newSource);
    const firstCommit = ref(repo.remote, 'refs/heads/gh-pages');
    assert.equal(ref(repo.remote, 'refs/tags/provider-policy-r2'), firstCommit, 'failed readback never rolls back the committed anchor');
    assert.equal(JSON.parse(show(repo.remote, firstCommit, FEED_PATH)).providers.length, 1, 'the committed snapshot remains historical, not silently edited');
    assert.equal(readFileSync(process.env.GITHUB_OUTPUT, 'utf8'), '', 'no deploy-ready commit output follows the detected race');
    // A fresh main checkout must not reconcile the older artifact as current success.
    git(repo.local, ['checkout', '--quiet', '--detach', newSource]); process.env.GITHUB_SHA = newSource;
    await assert.rejects(publish(repo.local, artifact, artifactDigest), /artifact source is no longer current/);
    const successor = join(repo.root, 'successor-artifact'); Date.now = () => input.now + 120000;
    await prepare(repo.local, successor);
    const successorDigest = sha256(readFileSync(join(successor, 'manifest.json')));
    const recoveredCommit = await publish(repo.local, successor, successorDigest);
    const recovered = JSON.parse(show(repo.remote, recoveredCommit, FEED_PATH));
    assert.equal(recovered.revision, 3); assert.deepEqual(recovered.providers, []);
    assert.equal(ref(repo.remote, 'refs/tags/provider-policy-r2'), firstCommit);
    assert.equal(ref(repo.remote, 'refs/tags/provider-policy-r3'), recoveredCommit);
    await verifyLive(successor, successorDigest, async (url) => {
      const path = new URL(url).pathname.replace(/^\/reference\//, '');
      const response = new Response(show(repo.remote, recoveredCommit, path));
      Object.defineProperty(response, 'url', { value: url }); return response;
    }, Date.now);
    await assert.rejects(publish(repo.local, artifact, artifactDigest), /artifact source is no longer current/);
    writeFileSync(process.env.GITHUB_OUTPUT, ''); writeFileSync(readbackFailure, 'simulate unavailable source readback');
    await assert.rejects(publish(repo.local, successor, successorDigest), /current source readback failed.*Do not request a Pages build/);
    assert.equal(readFileSync(process.env.GITHUB_OUTPUT, 'utf8'), '');
    assert.equal(ref(repo.remote, 'refs/heads/gh-pages'), recoveredCommit);
    assert.equal(await publish(repo.local, successor, successorDigest), recoveredCommit, 'retry after readback recovery reconciles exact committed bytes');
  } finally {
    Date.now = realNow;
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    repo.close();
  }
});
