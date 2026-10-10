#!/usr/bin/env node
// In a repository checkout the TypeScript source is present and is what runs (through tsx), so a build that is older
// than the source is never used by mistake. An installed package ships no source and runs its compiled build.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
let cli;
if (existsSync(here('../src/cli.ts'))) {
  const { register } = await import('tsx/esm/api');
  register();
  cli = await import('../src/cli.ts');
} else if (existsSync(here('../dist/cli.js'))) {
  cli = await import('../dist/cli.js');
} else {
  console.error('agentlogin: no build found (dist/cli.js is missing); reinstall the package');
  process.exit(1);
}
await cli.main(process.argv.slice(2));
