// Beta release preparation is local and read-only with respect to the registry.
// Publication is a separate, explicit command restricted to the canonical CI job.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const registry = 'https://registry.npmjs.org/';
export const repository = 'git+https://github.com/agentlogin/reference.git';
// Dependencies precede consumers. The AgentID adapter is a separate experimental integration.
export const packageFolders = ['agentlogin', 'issuer', 'conformance', 'agentid-mcp', 'rp', 'mcp', 'store-postgres', 'rp-store-postgres'];
const root = fileURLToPath(new URL('..', import.meta.url));
const json = (path) => JSON.parse(readFileSync(path, 'utf8'));
const digest = (bytes, algorithm = 'sha256', encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const run = (command, args, cwd = root, options = {}) => execFileSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 8_000_000, stdio: ['ignore', 'pipe', 'pipe'], timeout: 180_000, ...options });
const git = (...args) => run('git', args).trim();
const assertClean = () => assert.equal(git('status', '--porcelain', '--untracked-files=normal'), '', 'Commit or remove release changes before preparing an artifact');

export function parsePackOutput(stdout, expectedName) {
  const parsed = JSON.parse(stdout);
  // npm 12 keys JSON pack results by name; earlier CLIs return an array.
  const entries = Array.isArray(parsed) ? parsed : Object.values(parsed);
  assert.equal(entries.length, 1, 'Exactly one package must be packed per command');
  const packed = entries[0];
  assert.equal(packed?.name, expectedName);
  assert.equal(typeof packed.filename, 'string');
  assert.equal(basename(packed.filename), packed.filename);
  assert.match(packed.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
  return packed;
}

export function validateManifests(manifests, version) {
  assert.match(version, /^0\.\d+\.\d+-beta\.[1-9]\d*$/, 'Only an explicit 0.x beta version may be released');
  assert.equal(manifests.length, packageFolders.length);
  const names = new Set(manifests.map((p) => p.name));
  assert.equal(names.size, packageFolders.length);
  const seen = new Set();
  for (const [i, p] of manifests.entries()) {
    assert.equal(p.name, packageFolders[i] === 'agentlogin' ? 'agentlogin' : `@agentlogin/${packageFolders[i]}`);
    assert.equal(p.private, undefined, `${p.name} must be public`);
    assert.equal(p.version, version, `${p.name} has a different version`);
    assert.equal(p.repository?.url, repository);
    assert.equal(p.repository?.directory, `packages/${packageFolders[i]}`);
    assert.deepEqual(p.publishConfig, { access: 'public', tag: 'beta', registry });
    assert.equal(p.license, 'Apache-2.0');
    assert.ok(p.files.includes('LICENSE'));
    for (const kind of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, target] of Object.entries(p[kind] ?? {})) {
        assert.doesNotMatch(target, /^(?:file:|link:|workspace:|git\+|https?:)/, `${p.name} must not ship a local or arbitrary-URL dependency`);
        if (names.has(name)) {
          assert.equal(target, version, `${p.name} must pin the exact internal version`);
          assert.ok(seen.has(name), `${p.name} must follow dependency ${name}`);
        }
      }
    }
    seen.add(p.name);
  }
}

export function validatePackedFiles(files, pkg) {
  const exact = new Set(['package.json', 'README.md', 'LICENSE', ...Object.values(pkg.bin ?? {})]);
  const optional = pkg.name === '@agentlogin/mcp'
    ? new Set(['skills/agent-login/SKILL.md', 'examples/config.json'])
    : pkg.name === '@agentlogin/agentid-mcp'
      ? new Set(['skills/agentid-sign-in/SKILL.md', 'examples/config.json', 'examples/mcp.json'])
      : new Set();
  for (const file of files) {
    assert.equal(typeof file, 'string');
    assert.ok(!isAbsolute(file) && !file.split('/').some((part) => part === '..' || part.startsWith('.')), `Unsafe packed path: ${file}`);
    assert.ok(exact.has(file) || optional.has(file) || /^dist\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+\.(?:js(?:\.map)?|d\.ts)$/.test(file)
      || (pkg.name === '@agentlogin/issuer' && /^static\/[a-zA-Z0-9_-]+\.(?:html|js|css|svg)$/.test(file)), `Unexpected packed file: ${file}`);
  }
  for (const entry of [pkg.main, pkg.types, ...Object.values(pkg.bin ?? {}), 'LICENSE']) {
    assert.ok(files.includes(entry), `Missing packed entry: ${entry}`);
  }
}

function inspectTarball(path, pkg) {
  // Reject link/device entries and traversal before any extraction.
  const entries = run('tar', ['-tzf', path], dirname(path)).trim().split('\n');
  const files = entries.map((entry) => {
    assert.ok(entry.startsWith('package/'));
    return entry.slice('package/'.length);
  });
  validatePackedFiles(files, pkg);
  const verbose = run('tar', ['-tvzf', path], dirname(path)).trim().split('\n');
  assert.ok(verbose.every((line) => line.startsWith('-')), 'Only regular files may be published');
  assert.equal(new Set(files).size, files.length, 'No duplicate archive entries');
  const packed = JSON.parse(run('tar', ['-xOzf', path, 'package/package.json'], dirname(path)));
  assert.deepEqual(packed, pkg, 'Packed manifest must equal reviewed source');
  assert.equal(run('tar', ['-xOzf', path, 'package/LICENSE'], dirname(path)), readFileSync(join(root, 'LICENSE'), 'utf8'));
  for (const file of files) {
    const contents = run('tar', ['-xOzf', path, `package/${file}`], dirname(path));
    assert.doesNotMatch(contents, /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\bnpm_[A-Za-z0-9]{20,}|\bgh[pousr]_[A-Za-z0-9]{30,}/, `Credential-like material in ${file}`);
  }
  return files.sort();
}

function cleanConsumer(out, packages) {
  const consumer = mkdtempSync(join(tmpdir(), 'agentlogin-release-consumer-'));
  try {
    const sourceLock = json(join(root, 'package-lock.json'));
    const dependencies = {};
    const locked = {};
    for (const [path, record] of Object.entries(sourceLock.packages)) {
      if (!path.startsWith('node_modules/') || record.link || record.dev) continue;
      assert.equal(path.slice('node_modules/'.length).includes('/node_modules/'), false, 'Review nested runtime dependencies before updating release lock generation');
      assert.match(record.resolved, /^https:\/\/registry\.npmjs\.org\//);
      assert.equal(typeof record.integrity, 'string');
      locked[path] = record;
    }
    for (const p of packages) {
      const resolved = `file:${join(out, p.filename)}`;
      dependencies[p.name] = resolved;
      const metadata = { ...sourceLock.packages[p.directory] };
      delete metadata.devDependencies;
      delete metadata.dev;
      locked[`node_modules/${p.name}`] = { ...metadata, resolved, integrity: p.integrity };
    }
    const manifest = { name: 'agentlogin-release-consumer', version: '0.0.0', private: true, type: 'module', dependencies };
    const lock = JSON.stringify({ name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages: { '': manifest, ...locked } }, null, 2);
    writeFileSync(join(consumer, 'package.json'), JSON.stringify(manifest));
    writeFileSync(join(consumer, 'package-lock.json'), lock);
    run('npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', join(consumer, 'cache'), '--registry', registry], consumer);
    assert.equal(readFileSync(join(consumer, 'package-lock.json'), 'utf8'), lock);
    for (const p of packages) {
      const installed = join(consumer, 'node_modules', p.name);
      assert.ok(!lstatSync(installed).isSymbolicLink(), 'Consumer must not use workspace links');
      run(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(p.name)}); if (!Object.keys(m).length) throw new Error('No exports');`], consumer);
      for (const entry of Object.values(json(join(installed, 'package.json')).bin ?? {})) {
        assert.match(run(process.execPath, [join(installed, entry), '--help'], consumer), /usage|agentlogin|agentid/i);
      }
    }
    return { isolatedInstall: true, workspaceLinks: false, importedPackages: packages.length, cliHelp: true, dependencyLockSha256: digest(lock) };
  } finally { rmSync(consumer, { recursive: true, force: true }); }
}

async function prepare(out) {
  assertClean();
  assert.ok(isAbsolute(out), 'Use an absolute output directory');
  assert.ok(relative(root, out).startsWith('..'), 'Release output must be outside the checkout');
  assert.ok(!existsSync(out), 'A release output directory cannot be overwritten');
  const manifests = packageFolders.map((folder) => json(join(root, 'packages', folder, 'package.json')));
  const version = manifests[0].version;
  validateManifests(manifests, version);
  const sourceCommit = git('rev-parse', 'HEAD');
  // Remove only generated compiler outputs: tsc incremental builds can retain deleted source files.
  for (const folder of [...packageFolders.map((name) => `packages/${name}`), 'examples/rp-hono']) {
    rmSync(join(root, folder, 'dist'), { recursive: true, force: true });
    for (const file of readdirSync(join(root, folder)).filter((name) => name.endsWith('.tsbuildinfo'))) rmSync(join(root, folder, file));
  }
  run('npm', ['run', 'build'], root, { stdio: 'inherit' });
  mkdirSync(out, { recursive: true });
  const packages = [];
  for (const [i, folder] of packageFolders.entries()) {
    const packed = parsePackOutput(run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', out], join(root, 'packages', folder)), manifests[i].name);
    assert.equal(basename(packed.filename), packed.filename);
    const path = join(out, packed.filename);
    const files = inspectTarball(path, manifests[i]);
    const bytes = readFileSync(path);
    assert.equal(packed.integrity, `sha512-${digest(bytes, 'sha512', 'base64')}`);
    packages.push({ name: manifests[i].name, version, directory: `packages/${folder}`, filename: packed.filename, sha256: digest(bytes), integrity: packed.integrity, files });
  }
  const consumer = cleanConsumer(out, packages);
  assertClean();
  assert.equal(git('rev-parse', 'HEAD'), sourceCommit, 'Source changed while building');
  const manifest = { schemaVersion: 1, version, distTag: 'beta', registry, repository, sourceCommit, lockSha256: digest(readFileSync(join(root, 'package-lock.json'))), node: process.version, npm: run('npm', ['--version']).trim(), consumer, packages };
  writeFileSync(join(out, 'release.json'), JSON.stringify(manifest, null, 2) + '\n');
  writeFileSync(join(out, 'SHA256SUMS'), [...packages.map((p) => `${p.sha256}  ${p.filename}`), `${digest(readFileSync(join(out, 'release.json')))}  release.json`].join('\n') + '\n');
  console.log(JSON.stringify({ prepared: out, version, sourceCommit, packages: packages.length, consumer }, null, 2));
}

export function verifyBundle(out) {
  assertClean();
  const manifest = json(join(out, 'release.json'));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.distTag, 'beta');
  assert.equal(manifest.registry, registry);
  assert.equal(manifest.repository, repository);
  assert.equal(manifest.sourceCommit, git('rev-parse', 'HEAD'));
  assert.equal(manifest.lockSha256, digest(readFileSync(join(root, 'package-lock.json'))));
  const manifests = packageFolders.map((folder) => json(join(root, 'packages', folder, 'package.json')));
  validateManifests(manifests, manifest.version);
  assert.equal(manifest.packages.length, manifests.length);
  assert.deepEqual(readdirSync(out).sort(), [...manifest.packages.map((p) => p.filename), 'release.json', 'SHA256SUMS'].sort());
  for (const [i, p] of manifest.packages.entries()) {
    assert.equal(p.name, manifests[i].name);
    assert.equal(p.version, manifest.version);
    assert.equal(p.directory, `packages/${packageFolders[i]}`);
    assert.equal(basename(p.filename), p.filename);
    const path = join(out, p.filename);
    assert.ok(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink());
    const bytes = readFileSync(path);
    assert.equal(digest(bytes), p.sha256);
    assert.equal(`sha512-${digest(bytes, 'sha512', 'base64')}`, p.integrity);
    assert.deepEqual(inspectTarball(path, manifests[i]), p.files);
  }
  const expectedSums = [...manifest.packages.map((p) => `${p.sha256}  ${p.filename}`), `${digest(readFileSync(join(out, 'release.json')))}  release.json`].join('\n') + '\n';
  assert.equal(readFileSync(join(out, 'SHA256SUMS'), 'utf8'), expectedSums);
  return manifest;
}

async function registryVersion(p) {
  const response = await fetch(`${registry}${encodeURIComponent(p.name)}/${p.version}`, { signal: AbortSignal.timeout(15_000) });
  if (response.status === 404) return null;
  assert.equal(response.status, 200, `Cannot check registry state for ${p.name}`);
  return response.json();
}

async function verifyRegistryTags(p) {
  const response = await fetch(`${registry}${encodeURIComponent(p.name)}`, { signal: AbortSignal.timeout(15_000) });
  assert.equal(response.status, 200, `Cannot read dist-tags for ${p.name}`);
  const metadata = await response.json();
  assert.notEqual(metadata['dist-tags']?.latest, p.version, `${p.name} beta must not be the latest release`);
  assert.equal(metadata['dist-tags']?.beta, p.version, `${p.name} beta dist-tag does not identify this release`);
}

export async function reconcilePublishedVersion(p, lookup = registryVersion, checkTags = verifyRegistryTags) {
  const existing = await lookup(p);
  if (!existing) return false;
  assert.equal(existing.dist?.integrity, p.integrity, `${p.name} already exists with different bytes`);
  await checkTags(p);
  return true;
}

export function validateDispatchCommit(releaseCommit, githubSha) {
  assert.match(releaseCommit, /^[0-9a-f]{40}$/);
  // npm provenance names GITHUB_SHA, independently of the checkout's HEAD.
  assert.equal(releaseCommit, githubSha, 'Release source must equal the workflow dispatch commit for truthful provenance');
}

async function publish(out) {
  assertClean();
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Publish only through the reviewed GitHub Actions workflow');
  assert.equal(process.env.GITHUB_REPOSITORY, 'agentlogin/reference');
  assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main', 'Dispatch the release workflow from main');
  const manifest = verifyBundle(out);
  assert.equal(process.env.RELEASE_VERSION, manifest.version);
  assert.equal(process.env.RELEASE_COMMIT, manifest.sourceCommit);
  validateDispatchCommit(manifest.sourceCommit, process.env.GITHUB_SHA);
  assert.equal(git('rev-parse', `refs/tags/v${manifest.version}^{commit}`), manifest.sourceCommit, 'Version tag must identify the reviewed source');
  git('merge-base', '--is-ancestor', manifest.sourceCommit, 'origin/main');
  // Preflight every immutable version before making any mutation. An identical
  // prior artifact is safe to resume; a different artifact is never overwritten.
  for (const p of manifest.packages) {
    await reconcilePublishedVersion(p);
  }
  for (const p of manifest.packages) {
    if (await reconcilePublishedVersion(p)) { console.log(`Verified existing ${p.name}@${p.version}`); continue; }
    // An uncertain publish is reconciled by immutable name/version+integrity on rerun.
    // Never build or execute package lifecycle scripts in the OIDC-enabled job.
    run('npm', ['publish', join(out, p.filename), '--access', 'public', '--tag', 'beta', '--provenance', '--ignore-scripts', '--registry', registry], root, { stdio: 'inherit' });
    assert.ok(await reconcilePublishedVersion(p), `${p.name} publication must be read back before proceeding`);
  }
  for (const p of manifest.packages) assert.ok(await reconcilePublishedVersion(p), `${p.name} is absent at final release verification`);
  console.log(`Verified all ${manifest.packages.length} published beta artifacts and distribution tags`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, output, ...extra] = process.argv.slice(2);
  try {
    assert.equal(extra.length, 0);
    assert.ok(output && isAbsolute(output), 'Usage: node scripts/release.mjs prepare|verify|publish /absolute/output');
    if (command === 'prepare') await prepare(output);
    else if (command === 'verify') { const release = verifyBundle(output); console.log(`Verified ${release.packages.length} packages at ${release.version}`); }
    else if (command === 'publish') await publish(output);
    else throw new Error('Unknown release command');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
