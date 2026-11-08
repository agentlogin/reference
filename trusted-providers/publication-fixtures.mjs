// Synthetic .example records only. These fixtures are never provider admissions.
import { readFileSync } from 'node:fs';
import { AREAS, FEED_URL, PROFILE, PROGRAMME } from './publisher.mjs';
import { sha256 } from './publication-git.mjs';

export const NOW = Date.parse('2026-11-08T12:00:00.000Z');
export const DATE = '2026-11-08T10:00:00.000Z';
export const EXPIRY = '2026-11-10T12:00:00.000Z';
export const sourceCommit = 'a'.repeat(40), pagesCommit = 'b'.repeat(40);
export const previousFeed = readFileSync(new URL('./v1.json', import.meta.url));
export function fixture() {
  const adoption = {
    version: 1, status: 'adopted', programme: PROGRAMME, profile: PROFILE, operator: 'Synthetic test operator',
    adoptedAt: '2026-11-08T09:00:00.000Z', adoptionUrl: 'https://programme.example/adoption', authority: 'programme-test',
    publication: { repository: 'agentlogin/reference', sourceBranch: 'main', branch: 'gh-pages', url: FEED_URL, bootstrapCommit: pagesCommit, bootstrapFeedSha256: sha256(previousFeed), lifetimeHours: 12 }, delegates: ['automated-test-reviewer'],
  };
  const decision = {
    id: 'synthetic-admission', action: 'admit', issuer: 'https://identity.provider.example', decidedAt: DATE,
    reviewUrl: 'https://programme.example/reviews/synthetic', authority: 'automated-test-reviewer', method: 'Synthetic deterministic unit fixture', reason: 'Testing publisher validation only', supersedes: null,
    handleDomains: ['mail.provider.example'], specRevision: 'c'.repeat(40), expiresAt: EXPIRY,
    affiliations: 'Synthetic operator owns this synthetic provider; not independent endorsement', sourceRevision: 'd'.repeat(40),
    evidence: AREAS.map((area) => ({ area, url: `https://programme.example/evidence/${area}`, observedAt: DATE, expiresAt: EXPIRY, result: 'pass' })),
  };
  return { adoption, decisions: { version: 1, decisions: [decision] }, previous: null, previousFeed, pagesCommit, sourceCommit, now: NOW };
}
export function administrativeDecision(prior, action = 'suspend', decidedAt = '2026-11-08T12:01:00.000Z') {
  return { id: `synthetic-${action}`, action, issuer: prior.issuer, decidedAt, reviewUrl: `https://programme.example/reviews/${action}`, authority: 'programme-test', method: 'Authenticated source decision', reason: 'Synthetic incident', supersedes: prior.id };
}
