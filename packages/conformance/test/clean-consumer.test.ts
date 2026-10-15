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
const packages = ['issuer', 'agentlogin', 'rp', 'store-postgres', 'rp-store-postgres', 'conformance', 'mcp'];

test('clean consumer installs only declared packed dependencies and runs the PostgreSQL pilot', { timeout: 180_000 }, async (t) => {
  const out = mkdtempSync(join(tmpdir(), 'agentlogin-consumer-'));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  const artifacts: string[] = [];
  for (const path of [...packages.map((name) => `packages/${name}`), 'examples/rp-hono']) {
    const packed = await run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', out], { cwd: join(root, path), maxBuffer: 2_000_000, signal: t.signal });
    artifacts.push(join(out, JSON.parse(packed.stdout)[0].filename));
  }
  writeFileSync(join(out, 'package.json'), JSON.stringify({ name: 'independent-consumer-pilot', private: true, type: 'module' }));
  // The normal dependency install/CI populates npm's cache. No repository node_modules symlink or source copy.
  await run('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', ...artifacts], { cwd: out, timeout: 90_000, maxBuffer: 2_000_000, signal: t.signal });
  for (const name of ['@agentlogin/issuer', 'agentlogin', '@agentlogin/rp', '@agentlogin/mcp', 'agentlogin-example-rp-hono']) {
    assert.equal(lstatSync(join(out, 'node_modules', name)).isSymbolicLink(), false);
  }
  const lock = readFileSync(join(out, 'package-lock.json'), 'utf8');
  assert.equal(lock.includes(root), false, 'no dependency points into the development tree');
  await run(process.execPath, ['--input-type=module', '-e', "await Promise.all(['@agentlogin/issuer','agentlogin','@agentlogin/rp','@agentlogin/store-postgres','@agentlogin/rp-store-postgres','@agentlogin/mcp','agentlogin-example-rp-hono'].map(p=>import(p)))"], { cwd: out, signal: t.signal, timeout: 15_000 });
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
