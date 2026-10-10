// Every package's manifest must point at files that the build emits and that `npm pack` ships; source-based tests
// cannot see a wrong `main` or `bin`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const packages = ['issuer', 'conformance', 'agentlogin', 'rp'];

for (const name of packages) {
  test(`package ${name}: manifest entry points exist, are packed and load`, async () => {
    const dir = join(root, 'packages', name);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name: string; main?: string; types?: string; bin?: Record<string, string>; exports?: Record<string, string | Record<string, string>> };
    const entries = [pkg.main, pkg.types, ...Object.values(pkg.bin ?? {}), ...Object.values(pkg.exports ?? {}).flatMap((e) => (typeof e === 'string' ? [e] : Object.values(e)))].filter((e): e is string => typeof e === 'string').map((e) => e.replace(/^\.\//, ''));
    assert.ok(pkg.main, 'main is declared');
    for (const e of entries) assert.ok(existsSync(join(dir, e)), `${pkg.name}: ${e} does not exist after the build`);
    const packed = (JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })) as Array<{ files: Array<{ path: string }> }>)[0]!.files.map((f) => f.path);
    for (const e of entries) assert.ok(packed.includes(e), `${pkg.name}: ${e} is not in the packed files`);
    const mod = await import(pathToFileURL(join(dir, pkg.main!)).href);
    assert.ok(Object.keys(mod).length > 0, 'the main module exports something');
    for (const bin of Object.values(pkg.bin ?? {})) {
      const out = execFileSync(process.execPath, [join(dir, bin), '--help'], { encoding: 'utf8' });
      assert.match(out, /usage|agentlogin/i);
    }
  });
}
