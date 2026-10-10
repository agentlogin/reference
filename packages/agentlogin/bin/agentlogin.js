#!/usr/bin/env node
// Prefers the compiled build; from a repository checkout without a build it runs the TypeScript source through tsx.
let cli;
try {
  cli = await import('../dist/cli.js');
} catch (e) {
  if (e?.code !== 'ERR_MODULE_NOT_FOUND') throw e;
  const { register } = await import('tsx/esm/api');
  register();
  cli = await import('../src/cli.ts');
}
await cli.main(process.argv.slice(2));
