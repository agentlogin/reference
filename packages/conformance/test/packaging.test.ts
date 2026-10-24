// Every package is packed for real, unpacked as an installed package would be, and loaded from there: the manifest's
// entry points must be files the tarball contains, and a command must run from the compiled build without the source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parsePackOutput } from '../../../scripts/release.mjs';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const packages = ['issuer', 'conformance', 'agentlogin', 'rp', 'store-postgres', 'rp-store-postgres'];

for (const name of packages) {
  test(`package ${name}: the packed tarball has its entry points and runs without the source`, async (t) => {
    const dir = join(root, 'packages', name);
    const out = mkdtempSync(join(tmpdir(), `al-pack-${name}-`));
    t.after(() => rmSync(out, { recursive: true, force: true }));
    // `npm pack` runs the package's prepack script, which builds: a tarball never ships a stale or missing build.
    const packageName = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).name;
    const tarball = parsePackOutput(execFileSync('npm', ['pack', '--json', '--pack-destination', out], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }), packageName).filename;
    execFileSync('tar', ['-xzf', join(out, tarball), '-C', out]);
    const installed = join(out, 'package');
    symlinkSync(join(root, 'node_modules'), join(installed, 'node_modules')); // its dependencies, as an install would provide them
    const pkg = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')) as { name: string; main?: string; types?: string; bin?: Record<string, string>; exports?: Record<string, string | Record<string, string>> };
    const entries = [pkg.main, pkg.types, ...Object.values(pkg.bin ?? {}), ...Object.values(pkg.exports ?? {}).flatMap((e) => (typeof e === 'string' ? [e] : Object.values(e)))].filter((e): e is string => typeof e === 'string');
    assert.ok(pkg.main, 'main is declared');
    for (const e of entries) assert.ok(existsSync(join(installed, e)), `${pkg.name}: ${e} is not in the tarball`);
    assert.equal(existsSync(join(installed, 'src')), false, 'the source is not shipped, so the command below runs the build');
    const mod = await import(pathToFileURL(join(installed, pkg.main!)).href);
    assert.ok(Object.keys(mod).length > 0, 'the main module exports something');
    for (const bin of Object.values(pkg.bin ?? {})) {
      const help = execFileSync(process.execPath, [join(installed, bin), '--help'], { encoding: 'utf8' });
      assert.match(help, /usage|agentlogin/i);
    }
  });
}
