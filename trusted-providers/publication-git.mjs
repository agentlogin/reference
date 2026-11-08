import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { encode, validateState } from './publisher.mjs';

export const TAG_PREFIX = 'provider-policy-r';
export const FEED_PATH = 'trusted-providers/v1.json';
export const STATE_PATH = 'trusted-providers/publication-state.json';
export const SITE_FILES = ['.nojekyll', 'LICENSE', 'applications.json', 'catalog.schema.json', 'index.html', 'providers.json', 'trusted-providers/index.html', STATE_PATH, FEED_PATH].sort();
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export function git(cwd, args, options = {}) { return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 5 * 1024 * 1024, timeout: 30000, ...options }); }
export const ref = (cwd, name) => git(cwd, ['rev-parse', '--verify', `${name}^{commit}`]).trim();
export const show = (cwd, commit, path) => Buffer.from(git(cwd, ['show', `${commit}:${path}`]));
export function ancestor(cwd, before, after) {
  try { git(cwd, ['merge-base', '--is-ancestor', before, after]); return true; } catch { return false; }
}

/** Release tags are protected append-only anchors, independent of a restored Pages branch. */
export function publicationBase(cwd, pagesCommit, sourceCommit) {
  const tags = git(cwd, ['for-each-ref', '--format=%(refname:short) %(objecttype) %(objectname)', `refs/tags/${TAG_PREFIX}*`]).trim().split('\n').filter(Boolean).map((line) => {
    const [name, type, commit] = line.split(' ');
    if (!new RegExp(`^${TAG_PREFIX}[1-9][0-9]*$`).test(name) || type !== 'commit') throw new Error('invalid publication anchor');
    const revision = Number(name.slice(TAG_PREFIX.length));
    if (!Number.isSafeInteger(revision) || revision < 2) throw new Error('invalid publication anchor revision');
    return { name, revision, commit };
  }).sort((a, b) => a.revision - b.revision);
  if (tags.some((tag, i) => tag.revision !== i + 2)) throw new Error('publication anchor history is incomplete');
  const anchor = tags.at(-1);
  const previousFeed = show(cwd, pagesCommit, FEED_PATH);
  if (!anchor) {
    try { show(cwd, pagesCommit, STATE_PATH); } catch { return { anchor: null, previous: null, previousFeed }; }
    throw new Error('active publication state has lost its release anchor');
  }
  if (!ancestor(cwd, anchor.commit, pagesCommit)) throw new Error('Pages branch was restored behind the latest publication anchor');
  const stateBytes = show(cwd, pagesCommit, STATE_PATH);
  if (!stateBytes.equals(show(cwd, anchor.commit, STATE_PATH)) || !previousFeed.equals(show(cwd, anchor.commit, FEED_PATH))) throw new Error('Pages publication was changed outside the anchored publisher');
  const previous = validateState(JSON.parse(stateBytes), previousFeed);
  if (previous.revision !== anchor.revision) throw new Error('anchor and state revisions disagree');
  if (!ancestor(cwd, previous.sourceCommit, sourceCommit)) throw new Error('source history was restored behind the last publication');
  return { anchor, previous, previousFeed };
}

function filesUnder(path, relative = '') {
  const files = [];
  for (const entry of readdirSync(join(path, relative))) {
    const name = relative ? `${relative}/${entry}` : entry;
    const stat = lstatSync(join(path, name));
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new Error('artifact contains non-regular files');
    if (stat.isDirectory()) files.push(...filesUnder(path, name)); else files.push(name);
  }
  return files.sort();
}
export function stageArtifact(directory, files, identity) {
  if (existsSync(directory)) throw new Error('artifact directory must be new');
  if (JSON.stringify(Object.keys(files).sort()) !== JSON.stringify(SITE_FILES)) throw new Error('incomplete site artifact');
  mkdirSync(join(directory, 'site'), { recursive: true });
  const hashes = {};
  for (const path of SITE_FILES) {
    const body = Buffer.from(files[path]);
    if (body.length > 2 * 1024 * 1024) throw new Error('site file is too large');
    mkdirSync(join(directory, 'site', path, '..'), { recursive: true });
    writeFileSync(join(directory, 'site', path), body);
    hashes[path] = sha256(body);
  }
  const manifest = { version: 1, ...identity, files: hashes };
  const bytes = encode(manifest); writeFileSync(join(directory, 'manifest.json'), bytes);
  return sha256(bytes);
}
export function readArtifact(directory, expectedManifestSha256) {
  if (!/^[a-f0-9]{64}$/.test(expectedManifestSha256)) throw new Error('missing expected artifact digest');
  for (const part of [directory, join(directory, 'site')]) {
    const stat = lstatSync(part); if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('artifact root must be a regular directory');
  }
  const manifestStat = lstatSync(join(directory, 'manifest.json'));
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.size > 65536) throw new Error('invalid artifact manifest file');
  const bytes = readFileSync(join(directory, 'manifest.json'));
  if (sha256(bytes) !== expectedManifestSha256) throw new Error('artifact manifest changed');
  const manifest = JSON.parse(bytes);
  if (manifest.version !== 1 || JSON.stringify(filesUnder(join(directory, 'site'))) !== JSON.stringify(SITE_FILES) || JSON.stringify(Object.keys(manifest.files ?? {}).sort()) !== JSON.stringify(SITE_FILES)) throw new Error('incomplete or unexpected site artifact');
  const files = {};
  for (const path of SITE_FILES) {
    const stat = lstatSync(join(directory, 'site', path));
    if (stat.size > 2 * 1024 * 1024) throw new Error('site file is too large');
    files[path] = readFileSync(join(directory, 'site', path));
    if (sha256(files[path]) !== manifest.files[path]) throw new Error('site artifact changed');
  }
  return { manifest, files };
}

/** Create a commit using a private temporary index; never mutate the source checkout. */
export function createPublicationCommit(cwd, pagesCommit, files, revision, indexPath) {
  const env = { ...process.env, GIT_INDEX_FILE: indexPath, GIT_AUTHOR_NAME: 'Agent Login policy publisher', GIT_AUTHOR_EMAIL: 'policy-publisher@users.noreply.github.com', GIT_COMMITTER_NAME: 'Agent Login policy publisher', GIT_COMMITTER_EMAIL: 'policy-publisher@users.noreply.github.com' };
  git(cwd, ['read-tree', pagesCommit], { env });
  // Replace only this documented generated-site set. Other branch metadata is preserved.
  for (const path of SITE_FILES) {
    const object = git(cwd, ['hash-object', '-w', '--stdin'], { env, input: files[path] }).trim();
    git(cwd, ['update-index', '--add', '--cacheinfo', `100644,${object},${path}`], { env });
  }
  const tree = git(cwd, ['write-tree'], { env }).trim();
  return git(cwd, ['commit-tree', tree, '-p', pagesCommit, '-m', `Publish trusted-provider revision ${revision}`], { env }).trim();
}

/** Atomic non-force update: competing publishers cannot partly create a tag or replace a winner. */
export function pushPublication(cwd, commit, revision, remote = 'origin') {
  return git(cwd, ['push', '--atomic', remote, `${commit}:refs/heads/gh-pages`, `${commit}:refs/tags/${TAG_PREFIX}${revision}`]);
}
