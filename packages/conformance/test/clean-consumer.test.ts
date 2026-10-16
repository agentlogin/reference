import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../../..', import.meta.url));
const packages = ['issuer', 'agentlogin', 'rp', 'store-postgres', 'rp-store-postgres', 'conformance', 'mcp', 'agentid-mcp'];

test('clean consumer installs only declared packed dependencies and runs the PostgreSQL pilot', { timeout: 180_000 }, async (t) => {
  const out = mkdtempSync(join(tmpdir(), 'agentlogin-consumer-'));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  const sourceLock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  assert.equal(sourceLock.lockfileVersion, 3);
  const dependencies: Record<string, string> = {};
  const locked: Record<string, Record<string, unknown>> = {};
  // Keep the tested runtime graph. npm ci may cache tarballs without caching the
  // registry metadata that a later semver-based npm install --offline would need.
  for (const [path, record] of Object.entries(sourceLock.packages) as [string, Record<string, unknown>][]) {
    if (!path.startsWith('node_modules/') || record.link || record.dev) continue;
    assert.equal(path.slice('node_modules/'.length).includes('/node_modules/'), false, 'review nested dependency layouts before deriving this consumer lock');
    assert.match(String(record.resolved), /^https:\/\//);
    assert.equal(typeof record.integrity, 'string');
    locked[path] = record;
  }
  for (const path of [...packages.map((name) => `packages/${name}`), 'examples/rp-hono']) {
    const packed = await run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', out], { cwd: join(root, path), maxBuffer: 2_000_000, signal: t.signal });
    const artifact = JSON.parse(packed.stdout)[0];
    const metadata = { ...sourceLock.packages[path] };
    assert.equal(metadata.name ?? JSON.parse(readFileSync(join(root, path, 'package.json'), 'utf8')).name, artifact.name);
    assert.equal(metadata.version, artifact.version);
    assert.equal(sourceLock.packages[`node_modules/${artifact.name}`]?.resolved, path);
    assert.equal(sourceLock.packages[`node_modules/${artifact.name}`]?.link, true);
    delete metadata.devDependencies;
    delete metadata.dev;
    const resolved = `file:${artifact.filename}`;
    dependencies[artifact.name] = resolved;
    locked[`node_modules/${artifact.name}`] = { ...metadata, resolved, integrity: artifact.integrity };
  }
  assert.deepEqual(
    Object.entries(sourceLock.packages).filter(([, record]) => (record as { link?: boolean }).link).map(([path]) => path.slice('node_modules/'.length)).sort(),
    Object.keys(dependencies).sort(),
    'every workspace contributing runtime dependencies must be packed explicitly',
  );
  const manifest = { name: 'independent-consumer-pilot', version: '0.0.0', private: true, type: 'module', dependencies };
  writeFileSync(join(out, 'package.json'), JSON.stringify(manifest));
  const consumerLock = JSON.stringify({ name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages: { '': manifest, ...locked } });
  assert.equal(consumerLock.includes(root), false, 'no dependency points into the development tree');
  assert.equal(Object.values(locked).some((record) => record.link), false);
  writeFileSync(join(out, 'package-lock.json'), consumerLock);
  // A new cache proves this is independent of prior registry metadata and local
  // node_modules. Network access fetches only the immutable tarballs in the lock.
  await run('npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', join(out, 'npm-cache')], { cwd: out, timeout: 90_000, maxBuffer: 2_000_000, signal: t.signal });
  assert.equal(readFileSync(join(out, 'package-lock.json'), 'utf8'), consumerLock, 'npm ci preserves the exact tested resolutions');
  for (const name of Object.keys(dependencies)) {
    assert.equal(lstatSync(join(out, 'node_modules', name)).isSymbolicLink(), false);
  }
  await run(process.execPath, ['--input-type=module', '-e', "await Promise.all(['@agentlogin/issuer','agentlogin','@agentlogin/rp','@agentlogin/store-postgres','@agentlogin/rp-store-postgres','@agentlogin/mcp','@agentlogin/agentid-mcp','agentlogin-example-rp-hono'].map(p=>import(p)))"], { cwd: out, signal: t.signal, timeout: 15_000 });
  if (!process.env.AGENTLOGIN_TEST_POSTGRES_URL) {
    assert.notEqual(process.env.REQUIRE_POSTGRES_TESTS, '1', 'The required PostgreSQL consumer pilot needs AGENTLOGIN_TEST_POSTGRES_URL');
    t.diagnostic('Clean installation verified; PostgreSQL pilot not run because AGENTLOGIN_TEST_POSTGRES_URL is absent.');
    return;
  }
  copyFileSync(new URL('./consumer-pilot.mjs', import.meta.url), join(out, 'pilot.mjs'));
  const { stdout } = await run(process.execPath, ['pilot.mjs'], { cwd: out, timeout: 60_000, maxBuffer: 2_000_000, signal: t.signal });
  const evidence = JSON.parse(stdout.trim());
  assert.deepEqual(evidence, { installedPackages: true, postgres: true, signIn: true, persistedAction: true, crossInstance: true, logout: true, helperSession: true, revokedActionDenied: true });
});
