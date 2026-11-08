import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { monitorPolicy, writeMonitorReport } from './monitor.mjs';
import { compilePublication, encode, FEED_URL } from './publisher.mjs';
import { fixture, previousFeed, NOW } from './publication-fixtures.mjs';

function response(body, change = {}) {
  return async (url, options) => {
    assert.equal(url, FEED_URL);
    assert.deepEqual(options, { maxBytes: 65536, timeoutMs: 10000, maxRedirects: 0, allowPrivate: false, accept: 'application/json', headers: { 'cache-control': 'no-cache' } });
    assert.ok(!('authorization' in options.headers));
    return { url, status: 200, headers: {}, redirects: [], body, ...change };
  };
}
async function active() { const input = fixture(); const publication = await compilePublication(input); return { input, publication }; }

test('unconfigured historical draft is explicitly inactive, even after its original expiry', async () => {
  const report = await monitorPolicy({ expectedDraft: previousFeed, fetcher: response(previousFeed), now: () => NOW });
  assert.equal(report.status, 'inactive'); assert.equal(report.mode, 'inactive'); assert.equal(report.acceptedProviders, 0);
  assert.equal(report.deliveryVerified, false); assert.match(report.message, /not an active-service health check/);
});

test('unconfigured programme rejects an unexpected active, changed or malformed draft', async () => {
  const { publication } = await active();
  for (const bytes of [publication.body, Buffer.from('{}'), Buffer.concat([previousFeed, Buffer.from('\n')]), Buffer.from([0xff])]) {
    const report = await monitorPolicy({ expectedDraft: previousFeed, fetcher: response(bytes), now: () => NOW });
    assert.equal(report.status, 'alert'); assert.equal(report.code, 'inactive_publication_changed');
  }
  const wrong = encode({ ...JSON.parse(previousFeed), version: 999 });
  const invalidButMatching = await monitorPolicy({ expectedDraft: wrong, fetcher: response(wrong), now: () => NOW });
  assert.equal(invalidButMatching.status, 'alert', 'matching bytes alone cannot bypass actual SDK validation');
});

test('healthy active policy is validated by SDK and reports absolute runway', async () => {
  const { input, publication } = await active();
  const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => NOW });
  assert.equal(report.status, 'healthy'); assert.equal(report.mode, 'active'); assert.equal(report.revision, 2);
  assert.equal(report.releaseRemainingSeconds, 43200); assert.equal(report.releaseThresholdSeconds, 7200);
  assert.equal(report.acceptedProviders, 1); assert.deepEqual(report.expiringProviders, []);
});

test('release expiry threshold is inclusive and expired or future feeds fail closed', async () => {
  const { input, publication } = await active();
  const deadline = Date.parse(publication.state.expiresAt);
  for (const [now, expected] of [[deadline - 7200001, 'healthy'], [deadline - 7200000, 'alert'], [deadline - 1, 'alert'], [deadline, 'alert'], [NOW - 1, 'alert']]) {
    const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => now });
    assert.equal(report.status, expected, String(now));
  }
  const atThreshold = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => deadline - 7200000 });
  assert.equal(atThreshold.code, 'expiry_threshold');
});

test('provider review expiry warns independently of a freshly renewed feed', async () => {
  const input = fixture(); input.decisions.decisions[0].expiresAt = new Date(NOW + 7200000).toISOString();
  const publication = await compilePublication(input);
  const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => NOW });
  assert.equal(report.status, 'alert'); assert.equal(report.code, 'expiry_threshold'); assert.equal(report.releaseRemainingSeconds, 43200);
  assert.deepEqual(report.expiringProviders, [{ issuer: input.decisions.decisions[0].issuer, remainingSeconds: 7200 }]);
  const expired = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => NOW + 7200000 });
  assert.equal(expired.status, 'alert'); assert.equal(expired.code, 'invalid_or_expired_policy');
});

test('valid empty active releases are healthy without implying providers are accepted', async () => {
  const { input, publication } = await active();
  const empty = encode({ ...JSON.parse(publication.body), providers: [] });
  const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(empty), now: () => NOW });
  assert.equal(report.status, 'healthy'); assert.equal(report.acceptedProviders, 0);
  assert.match(report.message, /accepts no providers/); assert.match(report.message, /empty release is valid/);
});

test('short adopted release lifetimes use a proportional warning threshold', async () => {
  const input = fixture(); input.adoption.publication.lifetimeHours = 1;
  const publication = await compilePublication(input);
  const healthy = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => NOW });
  assert.equal(healthy.status, 'healthy'); assert.equal(healthy.releaseThresholdSeconds, 900);
  const warning = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body), now: () => NOW + 45 * 60000 });
  assert.equal(warning.status, 'alert'); assert.equal(warning.code, 'expiry_threshold');
});

test('read-only fetch bounds reject redirect, unexpected endpoint, oversized and failed responses', async () => {
  const { input, publication } = await active();
  for (const changes of [{ status: 503 }, { status: 302 }, { url: 'https://attacker.example/policy' }, { redirects: ['https://other.example/'] }, { body: Buffer.alloc(65537) }, { body: '{}' }]) {
    const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(publication.body, changes), now: () => NOW });
    assert.equal(report.status, 'alert'); assert.equal(report.code, 'fetch_failed');
  }
  const network = await monitorPolicy({ adoption: input.adoption, fetcher: async () => { throw new Error('network failure'); }, now: () => NOW });
  assert.equal(network.code, 'fetch_failed');
});

test('malformed policy metadata and invalid adoption cannot report healthy', async () => {
  const { input, publication } = await active();
  for (const bytes of [Buffer.from('{'), encode({ ...JSON.parse(publication.body), extra: 'unknown' }), encode({ ...JSON.parse(publication.body), profile: 'different-profile' }), previousFeed]) {
    const report = await monitorPolicy({ adoption: input.adoption, fetcher: response(bytes), now: () => NOW });
    assert.equal(report.status, 'alert'); assert.equal(report.code, 'invalid_or_expired_policy');
  }
  const invalid = await monitorPolicy({ adoption: {}, fetcher: async () => { throw new Error('must not fetch'); }, now: () => NOW });
  assert.equal(invalid.code, 'invalid_configuration');
});

test('expiry is checked after network latency, not using the start time', async () => {
  const { input, publication } = await active(); let clock = NOW;
  const report = await monitorPolicy({ adoption: input.adoption, now: () => clock, fetcher: async (...args) => { clock = Date.parse(publication.state.expiresAt); return response(publication.body)(...args); } });
  assert.equal(report.status, 'alert'); assert.equal(report.code, 'invalid_or_expired_policy');
  assert.equal(report.checkedAt, publication.state.expiresAt);
});

test('synthetic dispatch creates a labelled failure record without network or service changes', async () => {
  const report = await monitorPolicy({ simulateFailure: true, fetcher: async () => { assert.fail('synthetic check contacted network'); }, now: () => NOW });
  assert.equal(report.status, 'synthetic_failure'); assert.equal(report.mode, 'synthetic'); assert.equal(report.deliveryVerified, false);
  assert.match(report.message, /SYNTHETIC TEST/); assert.match(report.message, /No live health was checked/);
  const root = mkdtempSync(join(tmpdir(), 'agentlogin-monitor-report-'));
  try {
    assert.equal(writeMonitorReport(join(root, 'output'), report, join(root, 'summary.md')), 1);
    assert.deepEqual(JSON.parse(readFileSync(join(root, 'output/monitor.json'))), report);
    assert.match(readFileSync(join(root, 'summary.md'), 'utf8'), /does not confirm alert delivery/);
    const inactive = await monitorPolicy({ expectedDraft: previousFeed, fetcher: response(previousFeed), now: () => NOW });
    assert.equal(writeMonitorReport(join(root, 'inactive'), inactive), 0);
    assert.equal(JSON.parse(readFileSync(join(root, 'inactive/monitor.json'))).status, 'inactive');
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('workflow CLI synthetic failure exits nonzero and writes a labelled artifact without source files', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentlogin-monitor-cli-'));
  try {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('./monitor.mjs', import.meta.url)), join(root, 'report')], { cwd: root, env: { SIMULATE_FAILURE: 'true' }, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 1); assert.match(result.stdout, /::error title=SYNTHETIC/);
    const report = JSON.parse(readFileSync(join(root, 'report/monitor.json')));
    assert.equal(report.status, 'synthetic_failure'); assert.equal(report.mode, 'synthetic'); assert.equal(report.deliveryVerified, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
