#!/usr/bin/env node
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compilePublication, encode, time, assertSdkFeed, FEED_URL } from './publisher.mjs';
import { git, ref, show, publicationBase, stageArtifact, readArtifact, createPublicationCommit, pushPublication, FEED_PATH, STATE_PATH, TAG_PREFIX, sha256 } from './publication-git.mjs';

const SOURCE_FILES = ['trusted-providers/adoption.json', 'trusted-providers/decisions.json'];
function output(name, value) { if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`); }
function requireCanonicalRepository(cwd) {
  if (process.env.GITHUB_REPOSITORY !== 'agentlogin/reference' || process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('publisher runs only on the canonical main branch');
  if (!/^https:\/\/github\.com\/agentlogin\/reference(?:\.git)?$/.test(git(cwd, ['remote', 'get-url', 'origin']).trim())) throw new Error('unexpected publication remote');
}
function refresh(cwd) {
  git(cwd, ['fetch', '--no-recurse-submodules', '--tags', 'origin', 'refs/heads/main:refs/remotes/origin/main', 'refs/heads/gh-pages:refs/remotes/origin/gh-pages']);
  const sourceCommit = ref(cwd, 'HEAD');
  if (sourceCommit !== process.env.GITHUB_SHA || sourceCommit !== ref(cwd, 'refs/remotes/origin/main')) throw new Error('source is no longer current main; dispatch a fresh run');
  return { sourceCommit, pagesCommit: ref(cwd, 'refs/remotes/origin/gh-pages') };
}
// The release is a validated source snapshot, not a lock on main. Read back immediately
// after committing (and when reconciling) so observed newer decisions prevent deployment.
function confirmSourceAfterCommit(cwd, expectedSource, revision, commit) {
  const context = `Revision ${revision} is committed as ${commit}`;
  let source;
  try {
    const result = git(cwd, ['ls-remote', 'origin', 'refs/heads/main']).trim();
    if (!/^[0-9a-f]{40}\s+refs\/heads\/main$/.test(result)) throw new Error('invalid source ref response');
    source = result.split(/\s/)[0];
  } catch (cause) {
    throw new Error(`${context}, but current source readback failed. Do not request a Pages build; prepare a higher revision from current main. Never roll back this commit.`, { cause });
  }
  if (source !== expectedSource) {
    throw new Error(`${context}, but source changed after the validated snapshot. Do not request a Pages build; prepare a superseding higher revision from current main. Never roll back this commit.`);
  }
}
function sourceRecords(cwd, commit) { return SOURCE_FILES.map((path) => { const bytes = show(cwd, commit, path); if (bytes.length > 2 * 1024 * 1024) throw new Error('source record too large'); return JSON.parse(bytes); }); }
function configured(cwd, commit) {
  const paths = git(cwd, ['ls-tree', '--name-only', commit, ...SOURCE_FILES]).trim().split('\n').filter(Boolean);
  if (paths.length === 0) return false;
  if (paths.length !== 2) throw new Error('adoption and decision records must both be present');
  return true;
}

export async function prepare(cwd, destination) {
  requireCanonicalRepository(cwd);
  const identity = refresh(cwd);
  const base = publicationBase(cwd, identity.pagesCommit, identity.sourceCommit);
  if (!configured(cwd, identity.sourceCommit)) {
    if (base.previous) throw new Error('active programme source records are missing');
    output('ready', 'false'); console.log('Programme remains inactive: no adoption and admission records.'); return;
  }
  const [adoption, decisions] = sourceRecords(cwd, identity.sourceCommit);
  const publication = await compilePublication({ adoption, decisions, ...base, ...identity, now: Date.now() });
  const files = {};
  for (const path of ['applications.json', 'catalog.schema.json', 'index.html', 'providers.json']) files[path] = readFileSync(join(cwd, 'catalogs/dist', path));
  files['.nojekyll'] = Buffer.alloc(0); files.LICENSE = readFileSync(join(cwd, 'LICENSE'));
  files['trusted-providers/index.html'] = Buffer.from(publication.html); files[FEED_PATH] = publication.body; files[STATE_PATH] = encode(publication.state);
  const artifactDigest = stageArtifact(destination, files, { ...identity, anchor: base.anchor, revision: publication.state.revision, issuedAt: publication.state.issuedAt, expiresAt: publication.state.expiresAt });
  output('ready', 'true'); output('digest', artifactDigest); output('revision', publication.state.revision);
  console.log(`Prepared revision ${publication.state.revision}; artifact SHA-256 ${artifactDigest}. No publication performed.`);
}

export async function publish(cwd, directory, expectedDigest) {
  requireCanonicalRepository(cwd);
  const { manifest, files } = readArtifact(directory, expectedDigest);
  const identity = refresh(cwd);
  const base = publicationBase(cwd, identity.pagesCommit, identity.sourceCommit);
  if (identity.sourceCommit !== manifest.sourceCommit) throw new Error('artifact source is no longer current; prepare a superseding release from current main');
  // If a previous attempt committed but its response was lost, reconcile exact immutable bytes.
  const remoteTag = `${TAG_PREFIX}${manifest.revision}`;
  const tagNames = git(cwd, ['tag', '--list', remoteTag]).trim();
  if (tagNames) {
    const commit = ref(cwd, `refs/tags/${remoteTag}`);
    if (identity.pagesCommit !== commit || !Object.entries(files).every(([path, bytes]) => bytes.equals(show(cwd, commit, path)))) throw new Error('revision already belongs to a different or superseded publication');
    if (time(manifest.expiresAt) <= Date.now()) throw new Error('committed publication expired; prepare a fresh revision');
    await assertSdkFeed(files[FEED_PATH], Date.now());
    confirmSourceAfterCommit(cwd, manifest.sourceCommit, manifest.revision, commit);
    output('commit', commit); console.log(`Reconciled previously committed revision ${manifest.revision}.`); return commit;
  }
  if (identity.sourceCommit !== manifest.sourceCommit || identity.pagesCommit !== manifest.pagesCommit) throw new Error('publication base changed; prepare a fresh artifact');
  if (JSON.stringify(base.anchor) !== JSON.stringify(manifest.anchor)) throw new Error('publication anchor changed');
  const [adoption, decisions] = sourceRecords(cwd, identity.sourceCommit);
  const publication = await compilePublication({ adoption, decisions, ...base, ...identity, now: time(manifest.issuedAt) });
  if (!files[FEED_PATH].equals(publication.body) || !files[STATE_PATH].equals(encode(publication.state)) || !files['trusted-providers/index.html'].equals(Buffer.from(publication.html)) || manifest.revision !== publication.state.revision || manifest.expiresAt !== publication.state.expiresAt) throw new Error('artifact differs from authenticated source decisions');
  if (Date.now() < time(manifest.issuedAt) || time(manifest.expiresAt) - Date.now() < 5 * 60000) throw new Error('artifact is stale or nearly expired');
  await assertSdkFeed(publication.body, Date.now()); // Recheck review expiry after any build/queue wait.
  const scratch = mkdtempSync(join(tmpdir(), 'agentlogin-policy-index-'));
  try {
    const commit = createPublicationCommit(cwd, identity.pagesCommit, files, manifest.revision, join(scratch, 'index'));
    try { pushPublication(cwd, commit, manifest.revision); }
    catch (error) {
      // Never retry blindly after an uncertain commit. Both refs must establish the exact result.
      const refs = git(cwd, ['ls-remote', 'origin', 'refs/heads/gh-pages', `refs/tags/${remoteTag}`]).trim().split('\n');
      if (refs.length !== 2 || refs.some((line) => line.split(/\s/)[0] !== commit)) throw error;
    }
    confirmSourceAfterCommit(cwd, manifest.sourceCommit, manifest.revision, commit);
    output('commit', commit); console.log(`Committed revision ${manifest.revision} as ${commit}; deployment verification remains.`); return commit;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

export async function verifyLive(directory, expectedDigest, fetcher = fetch, clock = Date.now) {
  const now = typeof clock === 'function' ? clock : () => clock;
  const { manifest, files } = readArtifact(directory, expectedDigest);
  if (time(manifest.expiresAt) <= now()) throw new Error('release expired before deployment verification');
  for (const path of [FEED_PATH, STATE_PATH, 'trusted-providers/index.html']) {
    const address = new URL(path, new URL('../', FEED_URL)).href;
    const response = await fetcher(address, { redirect: 'error', headers: { 'Cache-Control': 'no-cache' }, signal: AbortSignal.timeout(10000) });
    if (response.status !== 200 || response.url !== address || response.redirected) throw new Error('live publication response is invalid');
    const reader = response.body?.getReader(); if (!reader) throw new Error('live response has no body');
    const chunks = []; let length = 0;
    try { while (true) { const item = await reader.read(); if (item.done) break; length += item.value.length; if (length > 2 * 1024 * 1024) throw new Error('live publication is too large'); chunks.push(item.value); } }
    finally { await reader.cancel().catch(() => {}); }
    if (!Buffer.concat(chunks).equals(files[path])) throw new Error('deployment is incomplete, stale or changed');
  }
  await assertSdkFeed(files[FEED_PATH], now());
  console.log(`Verified exact live revision ${manifest.revision}; feed SHA-256 ${sha256(files[FEED_PATH])}.`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [command, directory, expectedDigest] = process.argv.slice(2);
  if (!['prepare', 'publish', 'verify-live'].includes(command) || !directory) throw new Error('usage: publish.mjs prepare|publish|verify-live ARTIFACT_DIRECTORY [EXPECTED_DIGEST]');
  if (command === 'prepare') await prepare(process.cwd(), resolve(directory));
  else if (command === 'publish') await publish(process.cwd(), resolve(directory), expectedDigest);
  else await verifyLive(resolve(directory), expectedDigest);
}
