#!/usr/bin/env node
import { runConformance } from '../src/index.js';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 1) {
  const a = process.argv[i]!;
  if (a.startsWith('--')) args.set(a.slice(2), process.argv[i + 1] ?? '');
}
const issuer = args.get('issuer');
if (!issuer) {
  console.error(
    'usage: agentlogin-conformance --issuer URL [--admin-token T] [--handle H --owner-credential C [--email-only-owner-credential C2]]\n' +
      '         [--open-client-id URL --open-redirect-uri URI] [--invalid-open-client-id URL --invalid-open-redirect-uri URI]\n' +
      '         [--relay-issuer URL] [--json]',
  );
  process.exit(2);
}
const report = await runConformance({
  issuer: issuer.replace(/\/+$/, ''),
  adminToken: args.get('admin-token'),
  handle: args.get('handle'),
  ownerCredential: args.get('owner-credential'),
  emailOnlyOwnerCredential: args.get('email-only-owner-credential'),
  openClient: args.get('open-client-id') ? { clientId: args.get('open-client-id')!, redirectUri: args.get('open-redirect-uri') ?? '' } : undefined,
  invalidOpenClients: args.get('invalid-open-client-id') ? [{ name: 'invalid document', clientId: args.get('invalid-open-client-id')!, redirectUri: args.get('invalid-open-redirect-uri') ?? '' }] : undefined,
  relayIssuer: args.get('relay-issuer'),
  log: args.has('json') ? undefined : (l) => console.log(l),
});
if (args.has('json')) console.log(JSON.stringify(report, null, 2));
else console.log(`\n${report.passed} passed, ${report.failed} failed, ${report.skipped} skipped`);
process.exit(report.failed ? 1 : 0);
