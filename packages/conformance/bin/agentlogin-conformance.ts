#!/usr/bin/env node
import { runConformance } from '../src/index.js';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 1) {
  const a = process.argv[i]!;
  if (a.startsWith('--')) args.set(a.slice(2), process.argv[i + 1] ?? '');
}
const issuer = args.get('issuer');
if (!issuer) {
  console.error('usage: agentlogin-conformance --issuer URL [--admin-token T] [--handle H --owner-credential C] [--open-client-id URL --open-redirect-uri URI] [--json]');
  process.exit(2);
}
const report = await runConformance({
  issuer: issuer.replace(/\/+$/, ''),
  adminToken: args.get('admin-token'),
  handle: args.get('handle'),
  ownerCredential: args.get('owner-credential'),
  openClient: args.get('open-client-id') ? { clientId: args.get('open-client-id')!, redirectUri: args.get('open-redirect-uri') ?? '' } : undefined,
  log: args.has('json') ? undefined : (l) => console.log(l),
});
if (args.has('json')) console.log(JSON.stringify(report, null, 2));
else console.log(`\n${report.passed} passed, ${report.failed} failed, ${report.skipped} skipped`);
process.exit(report.failed ? 1 : 0);
