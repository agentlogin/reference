#!/usr/bin/env node
// Prefers the compiled build; falls back to the TypeScript source when run from the repository with tsx available.
const run = (m) => m.main(process.argv.slice(2));
import('../dist/cli.js').then(run).catch(async (e) => {
  if (e && e.code === 'ERR_MODULE_NOT_FOUND') {
    try { await import('tsx/esm/api').then((tsx) => tsx.register()); return run(await import('../src/cli.ts')); } catch (e2) { throw e2; }
  }
  throw e;
}).catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
