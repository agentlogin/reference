// Draft publication only. Activating the programme requires a separately reviewed publisher.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { TrustedProviderPolicy, RelyingPartyError } from '@agentlogin/rp';

const feedUrl = 'https://agentlogin.github.io/reference/trusted-providers/v1.json';
const escape = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Validate using the actual consumer at issuance, without changing the historical draft. */
export async function prepareDraftPublication(input) {
  const body = Buffer.from(input);
  if (body.byteLength > 64 * 1024) throw new Error('draft feed is too large');
  const feed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  if (feed?.status !== 'draft' || !Array.isArray(feed.providers) || feed.providers.length !== 0) {
    throw new Error('this publisher accepts only an empty draft; programme activation requires separate review');
  }
  const policy = new TrustedProviderPolicy({
    url: feedUrl,
    now: () => Date.parse(feed.issuedAt) + 1,
    fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body }),
  });
  try {
    await policy.assertAccepted('https://provider.example', 'agent@provider.example');
    throw new Error('draft unexpectedly accepted an issuer');
  } catch (error) {
    // A malformed feed also fails closed. Only the specific valid-draft result is publishable.
    if (!(error instanceof RelyingPartyError) || error.code !== 'issuer_policy_unavailable' || error.cause?.message !== 'policy is not active') {
      throw new Error('draft feed failed SDK validation', { cause: error });
    }
  }

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer"><title>Agent Login trusted providers - draft programme</title><style>
*{box-sizing:border-box}body{margin:0;background:#f6f8f5;color:#182523;font:16px/1.6 system-ui,sans-serif}header,main,footer{max-width:900px;margin:auto;padding:28px}header,footer{border-bottom:1px solid #dce5df}h1{font-size:clamp(32px,6vw,52px);line-height:1.12;letter-spacing:-.04em}h2{font-size:24px}a{color:#176c4e;text-underline-offset:4px}a:focus-visible{outline:3px solid #68b392;outline-offset:4px}.status{background:#fff;border:1px solid #dce5df;border-radius:14px;padding:24px}dt{font-weight:600}dd{margin:0 0 12px;overflow-wrap:anywhere}code{font-size:14px;overflow-wrap:anywhere}footer{font-size:14px;color:#52665d}
</style></head><body><header><a href="../">Agent Login directory</a></header><main><h1>Trusted providers</h1><section class="status"><h2>Draft programme. No approved providers.</h2><p>The programme is not operational. Its published draft does not enable sign-in through any provider.</p></section><h2>A shared policy that websites can choose</h2><p>When operational, websites can explicitly choose this policy to receive reviewed provider additions, suspensions and removals. The website still controls agent permissions and its own sessions. Using Agent Login does not automatically subscribe a website.</p><p>SentFrom.ai and AgentID are directory candidates, not approved providers. A directory listing or a passing test suite does not establish programme admission.</p><p><a href="https://github.com/agentlogin/reference/tree/main/trusted-providers#readme">Read the draft programme and admission criteria</a> or <a href="https://github.com/agentlogin/reference/blob/main/trusted-providers/PUBLICATION.md">review the publication and activation requirements</a>.</p><h2>Historical draft feed</h2><p>The <a href="v1.json">machine-readable draft</a> retains its original dates and exact bytes. Rebuilding this page never renews it. An expired or inactive feed refuses new sign-ins; it does not fall back to directory candidates.</p><dl><dt>Revision</dt><dd>${escape(feed.revision)}</dd><dt>Original issue time</dt><dd>${escape(feed.issuedAt)}</dd><dt>Original expiry</dt><dd>${escape(feed.expiresAt)}</dd><dt>Fixed feed address</dt><dd><code>${escape(feedUrl)}</code></dd></dl><p>Initial activation requires an accountable programme operator, completed evidence-based provider decisions, and separately exercised publication and recovery controls. Reviews and decisions may be automated under published delegation; no human approval or reviewer quorum is required. Automated or affiliated review does not establish independent endorsement.</p></main><footer>This page publishes the programme draft, not a certification or an operational trust service.</footer></body></html>`;
  return { body, html };
}

/** Caller supplies its generated site directory, after validating all site inputs. */
export function writeDraftPublication(siteDirectory, publication) {
  const destination = join(siteDirectory, 'trusted-providers');
  mkdirSync(destination, { recursive: true });
  writeFileSync(join(destination, 'v1.json'), publication.body);
  writeFileSync(join(destination, 'index.html'), publication.html);
}
