// Command line of the conformance harness.
import { runConformance } from './index.js';

const USAGE = `usage: agentlogin-conformance --issuer URL <mode> [options]

Modes:
  --admin-token T                      the harness creates its own owners, agents and clients through the issuer's
                                       bootstrap API (reference issuer); every run uses fresh handles
  --handle H --owner-credential C      an existing Agent and its Owner Credential, plus a client:
      --client-id ID --client-secret S --redirect-uri URI     a Registered Client, or
      --open-client-id URL --open-redirect-uri URI            an Open Client
                                       checks that need more than this are reported as skipped

Options:
  --open-client-id URL --open-redirect-uri URI                Open Client checks (Section 4.2)
  --invalid-open-client-id URL --invalid-open-redirect-uri URI  a document the issuer must refuse (I-39)
  --email-only-owner-credential C      a credential from the one-time-code sign-in (I-45)
  --relay-issuer URL                   a Relay whose metadata the issuer can fetch (I-45, I-48)
  --json                               the report as JSON`;

export async function main(argv: string[]): Promise<void> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (!a.startsWith('--')) continue;
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) { args.set(a.slice(2), next); i += 1; } else args.set(a.slice(2), '');
  }
  const issuer = args.get('issuer');
  if (args.has('help') || !issuer) {
    console.log(USAGE);
    process.exitCode = args.has('help') ? 0 : 2;
    return;
  }
  const val = (k: string) => args.get(k) || undefined;
  try {
    const report = await runConformance({
      issuer, // exactly as given: Issuer Identifiers are compared as strings
      adminToken: val('admin-token'),
      handle: val('handle'),
      ownerCredential: val('owner-credential'),
      emailOnlyOwnerCredential: val('email-only-owner-credential'),
      client: val('client-id') ? { clientId: val('client-id')!, clientSecret: val('client-secret') ?? '', redirectUri: val('redirect-uri') ?? '' } : undefined,
      openClient: val('open-client-id') ? { clientId: val('open-client-id')!, redirectUri: val('open-redirect-uri') ?? '' } : undefined,
      invalidOpenClients: val('invalid-open-client-id') ? [{ name: 'invalid document', clientId: val('invalid-open-client-id')!, redirectUri: val('invalid-open-redirect-uri') ?? '' }] : undefined,
      relayIssuer: val('relay-issuer'),
      log: args.has('json') ? undefined : (l) => console.log(l),
    });
    if (args.has('json')) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`\nPartial probe report: ${report.passed} passed, ${report.failed} failed, ${report.skipped} skipped`);
      console.log('Counts cover the probes implemented by this harness; passing them alone does not establish full conformance. See the package README for coverage.');
    }
    process.exitCode = report.failed ? 1 : 0;
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 2;
  }
}
