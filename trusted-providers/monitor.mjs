#!/usr/bin/env node
// Read-only publication monitoring. It never renews a policy, changes a decision or sends credentials.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { safeFetch } from 'agentlogin';
import { prepareDraftPublication } from './build.mjs';
import { assertSdkFeed, FEED_URL, validateAdoption } from './publisher.mjs';

const TWO_HOURS = 2 * 3600000;
const iso = (now) => new Date(now).toISOString();
const baseReport = (now) => ({ version: 1, checkedAt: iso(now), feedUrl: FEED_URL, deliveryVerified: false });
const alert = (report, code, message) => ({ ...report, status: 'alert', code, message });

/** Trusted test clock/transport overrides; production uses safeFetch and synchronized wall time. */
export async function monitorPolicy({ adoption = null, expectedDraft, fetcher = safeFetch, now = Date.now, simulateFailure = false } = {}) {
  const report = { ...baseReport(now()), mode: adoption === null ? 'inactive' : 'active' };
  if (simulateFailure) return { ...report, mode: 'synthetic', status: 'synthetic_failure', code: 'synthetic_monitor_test', message: 'SYNTHETIC TEST: monitor failure path exercised. No live health was checked and no service or policy was changed.' };
  try { if (adoption !== null) validateAdoption(adoption, now()); }
  catch { return alert(report, 'invalid_configuration', 'Programme adoption is invalid. No active-policy health is asserted.'); }

  let response;
  try {
    response = await fetcher(FEED_URL, { maxBytes: 64 * 1024, timeoutMs: 10000, maxRedirects: 0, allowPrivate: false, accept: 'application/json', headers: { 'cache-control': 'no-cache' } });
    if (response.status !== 200 || response.url !== FEED_URL || response.redirects.length !== 0 || !Buffer.isBuffer(response.body) || response.body.length > 64 * 1024) throw new Error('invalid response');
  } catch { return alert({ ...report, checkedAt: iso(now()) }, 'fetch_failed', 'The fixed policy endpoint could not be read safely. Check publication and connectivity.'); }
  const bytes = response.body;
  const observed = { ...report, checkedAt: iso(now()), feedSha256: createHash('sha256').update(bytes).digest('hex') };
  if (adoption === null) {
    try {
      if (!Buffer.isBuffer(expectedDraft) || !bytes.equals(expectedDraft)) throw new Error('unexpected inactive publication');
      await prepareDraftPublication(bytes); // Actual SDK at the historical issuance, without renewing dates.
    } catch { return alert(observed, 'inactive_publication_changed', 'Unconfigured programme is not serving its exact validated historical draft. Investigate; no active-policy health is asserted.'); }
    return { ...observed, status: 'inactive', acceptedProviders: 0, message: 'INACTIVE: the programme has no adoption record and serves its unchanged historical draft. This is not an active-service health check.' };
  }

  let feed;
  try {
    feed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (feed.status !== 'active') throw new Error('adopted programme is inactive');
    await assertSdkFeed(bytes, now()); // Check the complete current feed with the production consumer.
  } catch { return alert(observed, 'invalid_or_expired_policy', 'The adopted programme has an invalid, inactive or expired policy, or an expired provider review. New sign-ins may be refused.'); }

  const checkedAt = now();
  const releaseRemainingMs = Date.parse(feed.expiresAt) - checkedAt;
  const reviewRemaining = feed.providers.map((provider) => ({ issuer: provider.issuer, remainingMs: Date.parse(provider.reviewExpiresAt) - checkedAt }));
  const releaseThresholdMs = Math.min(TWO_HOURS, adoption.publication.lifetimeHours * 3600000 / 4);
  const expiringProviders = reviewRemaining.filter((provider) => provider.remainingMs <= TWO_HOURS).map((provider) => ({ issuer: provider.issuer, remainingSeconds: Math.floor(provider.remainingMs / 1000) }));
  const details = { ...observed, checkedAt: iso(checkedAt), revision: feed.revision, issuedAt: feed.issuedAt, expiresAt: feed.expiresAt, acceptedProviders: feed.providers.length,
    releaseRemainingSeconds: Math.floor(releaseRemainingMs / 1000), releaseThresholdSeconds: releaseThresholdMs / 1000,
    reviewThresholdSeconds: TWO_HOURS / 1000, expiringProviders };
  if (releaseRemainingMs <= releaseThresholdMs || expiringProviders.length) {
    return alert(details, 'expiry_threshold', 'Policy or provider-review validity is at or below its monitoring threshold. Renew eligible publication or complete a new evidence-based decision before expiry.');
  }
  return { ...details, status: 'healthy', message: feed.providers.length ? 'Active policy and provider reviews exceed their expiry thresholds.' : 'Active policy exceeds its expiry threshold and accepts no providers. An empty release is valid during suspension, withdrawal or review expiry.' };
}

/** An artifact and annotation are an alert record, not evidence of delivery to an inbox. */
export function writeMonitorReport(directory, report, summaryFile) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'monitor.json'), `${JSON.stringify(report, null, 2)}\n`);
  const failed = report.status === 'alert' || report.status === 'synthetic_failure';
  const label = report.status === 'synthetic_failure' ? 'SYNTHETIC trusted-provider monitor test' : 'Trusted-provider policy monitor';
  const safe = (value) => String(value).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
  console.log(`::${failed ? 'error' : 'notice'} title=${label}::${safe(report.message)}`);
  if (summaryFile) appendFileSync(summaryFile, `${label}\n\nStatus: **${report.status}**. ${report.message}\n\nThis workflow record does not confirm alert delivery to support or independent monitoring availability.\n`);
  return failed ? 1 : 0;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const directory = process.argv[2];
  if (!directory) throw new Error('usage: monitor.mjs REPORT_DIRECTORY');
  let result;
  try {
    if (process.env.SIMULATE_FAILURE === 'true') result = await monitorPolicy({ simulateFailure: true });
    else {
      const adoptionPath = resolve('trusted-providers/adoption.json');
      const adoption = existsSync(adoptionPath) ? JSON.parse(readFileSync(adoptionPath, 'utf8')) : null;
      result = await monitorPolicy({ adoption, expectedDraft: readFileSync(resolve('trusted-providers/v1.json')) });
    }
  } catch {
    result = alert({ ...baseReport(Date.now()), mode: 'unknown' }, 'invalid_configuration', 'Monitor configuration could not be loaded. No publication-health claim is made.');
  }
  process.exitCode = writeMonitorReport(resolve(directory), result, process.env.GITHUB_STEP_SUMMARY);
}
