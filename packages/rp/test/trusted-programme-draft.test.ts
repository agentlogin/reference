import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { TrustedProviderPolicy, AGENTLOGIN_TRUSTED_PROVIDERS_URL } from '../src/trusted-providers.js';
import { RelyingPartyError } from '../src/errors.js';

test('the checked-in programme feed is a valid, empty draft and cannot admit catalog candidates', async () => {
  const body = await readFile(new URL('../../../trusted-providers/v1.json', import.meta.url));
  const feed = JSON.parse(body.toString('utf8'));
  assert.equal(feed.status, 'draft');
  assert.deepEqual(feed.providers, []);
  // Validate the historical draft at issuance. Its absolute dates are never renewed by a build.
  const policy = new TrustedProviderPolicy({ url: AGENTLOGIN_TRUSTED_PROVIDERS_URL,
    now: () => Date.parse(feed.issuedAt) + 1,
    fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body }) });
  for (const [issuer, handle] of [
    ['https://identity.sentfrom.ai', 'agent@mail.sentfrom.ai'],
    ['https://auth.agentid.com', 'agent@agentmail.to'],
  ]) {
    await assert.rejects(policy.assertAccepted(issuer!, handle), (error: unknown) => {
      assert.ok(error instanceof RelyingPartyError);
      assert.equal(error.code, 'issuer_policy_unavailable');
      assert.equal(error.status, 503);
      // Distinguishes a valid draft from a malformed fixture that happens to fail closed.
      assert.equal((error.cause as Error).message, 'policy is not active');
      return true;
    });
  }
});
