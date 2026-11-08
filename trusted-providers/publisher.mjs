// Active publication is deliberately separate from the historical draft builder.
import { createHash } from 'node:crypto';
import { TrustedProviderPolicy } from '@agentlogin/rp';

export const PROGRAMME = 'agentlogin-trusted-providers';
export const PROFILE = 'agent-login-core-1.0-draft-0.2-direct-es256';
export const FEED_URL = 'https://agentlogin.github.io/reference/trusted-providers/v1.json';
export const AREAS = ['operator', 'protocol', 'owner_authority', 'lifecycle', 'operations', 'privacy'];
export const APPROVALS = ['admit', 'renew', 'reinstate'];
const hash = (value) => createHash('sha256').update(value).digest('hex');
export const encode = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
export const digest = (value) => hash(encode(value));
const fail = (message) => { throw new Error(message); };
function keys(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || Object.keys(value).some((key) => !names.includes(key))) fail(`invalid ${label} fields`);
}
function text(value, label, max = 2048) {
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) fail(`invalid ${label}`);
  return value;
}
function sha(value) { if (typeof value !== 'string' || !/^[a-f0-9]{40}$/.test(value)) fail('invalid commit SHA'); return value; }
function id(value) { if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(value)) fail('invalid record id'); return value; }
export function time(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) fail('invalid timestamp');
  return Date.parse(value);
}
function url(value) {
  text(value, 'HTTPS URL');
  if (!value.startsWith('https://') || /[\s\\]/.test(value)) fail('invalid HTTPS URL');
  const parsed = new URL(value);
  if (!parsed.hostname || parsed.username || parsed.password || parsed.hash) fail('invalid HTTPS URL');
  return value;
}
function issuer(value) { url(value); const u = new URL(value); if (u.search || u.hash || (u.pathname === '/' ? u.origin !== value : u.href !== value)) fail('issuer must be canonical and have no trailing root slash'); }
function domains(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 100 || new Set(values).size !== values.length) fail('invalid handle domains');
  for (const value of values) if (typeof value !== 'string' || value.length > 253 || !value.includes('.') || !value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || /^\d+(\.\d+){3}$/.test(value)) fail('invalid handle domain');
  if (JSON.stringify([...values].sort()) !== JSON.stringify(values)) fail('handle domains must be sorted');
}

export function validateAdoption(adoption, now) {
  keys(adoption, ['version', 'status', 'programme', 'profile', 'operator', 'adoptedAt', 'adoptionUrl', 'authority', 'publication', 'delegates'], 'adoption');
  if (adoption.version !== 1 || adoption.status !== 'adopted' || adoption.programme !== PROGRAMME || adoption.profile !== PROFILE) fail('programme is not adopted for this profile');
  text(adoption.operator, 'operator'); url(adoption.adoptionUrl); text(adoption.authority, 'authority');
  if (time(adoption.adoptedAt) > now) fail('adoption is in the future');
  if (!Array.isArray(adoption.delegates) || adoption.delegates.length > 100 || new Set(adoption.delegates).size !== adoption.delegates.length) fail('invalid delegates');
  adoption.delegates.forEach((item) => text(item, 'delegate'));
  const p = adoption.publication;
  keys(p, ['repository', 'sourceBranch', 'branch', 'url', 'bootstrapCommit', 'bootstrapFeedSha256', 'lifetimeHours'], 'publication');
  if (p.repository !== 'agentlogin/reference' || p.sourceBranch !== 'main' || p.branch !== 'gh-pages' || p.url !== FEED_URL) fail('publication trust root is fixed');
  sha(p.bootstrapCommit);
  if (!/^[a-f0-9]{64}$/.test(p.bootstrapFeedSha256)) fail('invalid bootstrap digest');
  if (!Number.isInteger(p.lifetimeHours) || p.lifetimeHours < 1 || p.lifetimeHours > 24) fail('release lifetime must be 1 to 24 hours');
  return adoption;
}

/** Validate every historical decision, even if expired or superseded. Expiry never rewrites history. */
export function validateDecisions(input, adoption, now) {
  keys(input, ['version', 'decisions'], 'decision log');
  if (input.version !== 1 || !Array.isArray(input.decisions) || input.decisions.length > 10000) fail('invalid decision log');
  const ids = new Set(), latest = new Map();
  let lastTime = time(adoption.adoptedAt);
  for (const d of input.decisions) {
    const approval = APPROVALS.includes(d?.action);
    keys(d, ['id', 'action', 'issuer', 'decidedAt', 'reviewUrl', 'authority', 'method', 'reason', 'supersedes', ...(approval ? ['handleDomains', 'specRevision', 'expiresAt', 'affiliations', 'sourceRevision', 'evidence'] : [])], 'decision');
    id(d.id); if (ids.has(d.id)) fail('duplicate decision id'); ids.add(d.id);
    if (!approval && !['suspend', 'withdraw'].includes(d.action)) fail('invalid decision action');
    issuer(d.issuer); url(d.reviewUrl); text(d.authority, 'authority'); text(d.method, 'method'); text(d.reason, 'reason');
    if (d.authority !== adoption.authority && !adoption.delegates.includes(d.authority)) fail('decision authority is not delegated');
    const decided = time(d.decidedAt);
    if (decided < lastTime || decided > now) fail('decision chronology is invalid'); lastTime = decided;
    const prior = latest.get(d.issuer);
    if (d.supersedes !== (prior?.id ?? null)) fail('decision does not supersede the current issuer decision');
    if (d.action === 'admit' && prior) fail('existing issuer requires renewal or reinstatement');
    if (d.action !== 'admit' && !prior) fail('decision has no previous admission');
    if (d.action === 'renew' && !APPROVALS.includes(prior?.action)) fail('suspended or withdrawn issuer requires reinstatement');
    if (d.action === 'reinstate' && !['suspend', 'withdraw'].includes(prior?.action)) fail('reinstatement requires suspension or withdrawal');
    if (approval) {
      domains(d.handleDomains); sha(d.specRevision); sha(d.sourceRevision);
      text(d.affiliations, 'affiliations');
      if (time(d.expiresAt) <= decided) fail('decision expiry must follow the decision');
      if (!Array.isArray(d.evidence) || d.evidence.length !== AREAS.length) fail('all six evidence areas are required');
      const areas = new Set();
      for (const e of d.evidence) {
        keys(e, ['area', 'url', 'observedAt', 'expiresAt', 'result'], 'evidence');
        if (!AREAS.includes(e.area) || areas.has(e.area) || e.result !== 'pass') fail('evidence is incomplete or not passing');
        areas.add(e.area); url(e.url);
        if (time(e.observedAt) > decided || time(e.expiresAt) <= decided || time(e.expiresAt) <= time(e.observedAt) || time(d.expiresAt) > time(e.expiresAt)) fail('approval outlives or predates required evidence');
      }
    }
    latest.set(d.issuer, d);
  }
  return latest;
}

export function validateState(state, feedBytes) {
  keys(state, ['version', 'revision', 'sourceCommit', 'previousPublicationCommit', 'adoptionDigest', 'decisions', 'feedSha256', 'issuedAt', 'expiresAt'], 'publication state');
  if (state.version !== 1 || !Number.isSafeInteger(state.revision) || state.revision < 2) fail('invalid state revision');
  sha(state.sourceCommit); sha(state.previousPublicationCommit);
  if (![state.adoptionDigest, state.feedSha256].every((v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v))) fail('invalid state digest');
  if (!Array.isArray(state.decisions) || state.decisions.length > 10000) fail('invalid state decisions');
  const ids = new Set();
  for (const item of state.decisions) {
    keys(item, ['id', 'sha256'], 'state decision'); id(item.id);
    if (ids.has(item.id) || !/^[a-f0-9]{64}$/.test(item.sha256)) fail('invalid state decision digest'); ids.add(item.id);
  }
  time(state.issuedAt); time(state.expiresAt);
  const feed = JSON.parse(feedBytes);
  if (hash(feedBytes) !== state.feedSha256 || feed.revision !== state.revision || feed.issuedAt !== state.issuedAt || feed.expiresAt !== state.expiresAt || feed.status !== 'active') fail('published feed and state disagree');
  return state;
}

export async function assertSdkFeed(bytes, now) {
  const feed = JSON.parse(bytes);
  const policy = new TrustedProviderPolicy({ url: FEED_URL, now: () => now, fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body: bytes }) });
  if (feed.providers.length) {
    for (const provider of feed.providers) for (const domain of provider.handleDomains) await policy.assertAccepted(provider.issuer, `probe@${domain}`);
  } else {
    try { await policy.assertAccepted('https://unlisted.example', 'probe@unlisted.example'); fail('empty feed accepted an issuer'); }
    catch (error) { if (error.code !== 'issuer_not_accepted') throw error; }
  }
}

export async function compilePublication({ adoption, decisions, previous, previousFeed, pagesCommit, sourceCommit, now }) {
  if (!Number.isSafeInteger(now) || now < 0) fail('invalid publication clock');
  sha(sourceCommit); sha(pagesCommit); validateAdoption(adoption, now);
  const latest = validateDecisions(decisions, adoption, now);
  const decisionHashes = decisions.decisions.map((d) => ({ id: d.id, sha256: digest(d) }));
  if (previous) {
    validateState(previous, previousFeed);
    if (previous.adoptionDigest !== digest(adoption)) fail('adopted policy changed; requires a separately reviewed migration');
    if (now < time(previous.issuedAt)) fail('publication clock moved backwards');
    if (previous.decisions.length > decisionHashes.length || previous.decisions.some((v, i) => digest(v) !== digest(decisionHashes[i]))) fail('decision history changed or was restored backwards');
  } else if (pagesCommit !== adoption.publication.bootstrapCommit || hash(previousFeed) !== adoption.publication.bootstrapFeedSha256 || JSON.parse(previousFeed).status !== 'draft' || JSON.parse(previousFeed).revision !== 1 || JSON.parse(previousFeed).providers.length !== 0) {
    fail('initial activation must match the adopted historical draft exactly');
  }
  const providers = [...latest.values()].filter((d) => APPROVALS.includes(d.action) && time(d.expiresAt) > now).map((d) => ({ issuer: d.issuer, handleDomains: d.handleDomains, specRevision: d.specRevision, reviewUrl: d.reviewUrl, reviewExpiresAt: d.expiresAt })).sort((a, b) => a.issuer < b.issuer ? -1 : a.issuer > b.issuer ? 1 : 0);
  if (!previous && providers.length === 0) fail('initial activation requires a current completed admission');
  const revision = (previous?.revision ?? 1) + 1;
  if (!Number.isSafeInteger(revision)) fail('revision exhausted');
  const issuedAt = new Date(now).toISOString(), expiresAt = new Date(now + adoption.publication.lifetimeHours * 3600000).toISOString();
  const feed = { version: 1, programme: PROGRAMME, profile: PROFILE, status: 'active', revision, issuedAt, expiresAt, providers };
  const body = encode(feed);
  await assertSdkFeed(body, now);
  const state = { version: 1, revision, sourceCommit, previousPublicationCommit: pagesCommit, adoptionDigest: digest(adoption), decisions: decisionHashes, feedSha256: hash(body), issuedAt, expiresAt };
  return { body, state, html: renderPublication(feed, adoption, sourceCommit) };
}

const escape = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function renderPublication(feed, adoption, sourceCommit) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer"><title>Agent Login trusted providers</title><style>body{max-width:850px;margin:40px auto;padding:0 24px;color:#182523;font:16px/1.6 system-ui,sans-serif}a{color:#176c4e}li{margin:16px 0}code{overflow-wrap:anywhere}</style></head><body><a href="../">Agent Login directory</a><h1>Trusted providers</h1><p>This is an opt-in acceptance policy for direct Agent Login Core issuers. Websites keep control of agent permissions and application sessions.</p><p>Published revision ${feed.revision}. Valid from ${escape(feed.issuedAt)} until ${escape(feed.expiresAt)}. This static page can remain visible after expiry: clients check the feed's absolute expiry before accepting a sign-in.</p><h2>Providers in this release</h2>${feed.providers.length ? `<ul>${feed.providers.map((p) => `<li><code>${escape(p.issuer)}</code><br>Handle domains: ${p.handleDomains.map(escape).join(', ')}<br>Review expires ${escape(p.reviewExpiresAt)}. <a href="${escape(p.reviewUrl)}">Scope and evidence</a></li>`).join('')}</ul>` : '<p>No providers are accepted in this release.</p>'}<p>A provider also stops being accepted at its review expiry, even before this release expires. A listing does not guarantee availability or grant an agent permission to act.</p><h2>Accountability</h2><p>Programme operator: ${escape(adoption.operator)}. <a href="${escape(adoption.adoptionUrl)}">Adopted policy and authority</a>. Automated and affiliated decisions are permitted; they are not independent endorsement.</p><p><a href="v1.json">Machine-readable policy</a> · <a href="publication-state.json">Publication state</a> · <a href="https://github.com/agentlogin/reference/blob/${sourceCommit}/trusted-providers/decisions.json">Decision history at this release</a> · <a href="https://github.com/agentlogin/reference/blob/${sourceCommit}/trusted-providers/ACTIVE-PUBLICATION.md">Publication, suspension and recovery</a></p><p>Expired or unavailable policies refuse new sign-ins. Updates and CDN propagation are not instantaneous; websites can block an issuer locally.</p></body></html>`;
}
