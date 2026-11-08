import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TrustedProviderPolicy } from '@agentlogin/rp';
import { compilePublication, validateState, encode, FEED_URL } from './publisher.mjs';
import { fixture, administrativeDecision, NOW, EXPIRY } from './publication-fixtures.mjs';

async function next(input, changes = {}) {
  const prior = await compilePublication(input);
  return { ...input, previous: prior.state, previousFeed: prior.body, now: input.now + 60000, ...changes };
}

test('active publication requires adopted authority, all evidence areas and exact SDK-compatible scope', async () => {
  const p = await compilePublication(fixture());
  const feed = JSON.parse(p.body);
  assert.equal(feed.revision, 2); assert.equal(feed.status, 'active'); assert.equal(feed.providers.length, 1);
  assert.equal(feed.expiresAt, '2026-11-09T00:00:00.000Z');
  assert.equal(feed.providers[0].reviewExpiresAt, EXPIRY);
  assert.match(p.html, /Automated and affiliated decisions/);
  assert.match(p.html, /static page can remain visible after expiry/);
  assert.deepEqual(validateState(p.state, p.body), p.state);
  const policy = new TrustedProviderPolicy({ url: FEED_URL, now: () => NOW, fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body: p.body }) });
  await policy.assertAccepted('https://identity.provider.example', 'test@mail.provider.example');
  await assert.rejects(policy.assertAccepted('https://identity.provider.example', 'test@other.example'), { code: 'issuer_not_accepted' });
});

test('missing, failed, repeated or mistimed evidence cannot establish admission', async () => {
  for (const area of fixture().decisions.decisions[0].evidence.map((e) => e.area)) {
    const input = fixture(); input.decisions.decisions[0].evidence = input.decisions.decisions[0].evidence.filter((e) => e.area !== area);
    await assert.rejects(compilePublication(input), /six evidence/);
  }
  for (const change of [
    (d) => { d.evidence[0].result = 'untested'; },
    (d) => { d.evidence[0].area = d.evidence[1].area; },
    (d) => { d.evidence[0].observedAt = '2026-11-09T00:00:00.000Z'; },
    (d) => { d.evidence[0].expiresAt = '2026-11-08T11:00:00.000Z'; },
    (d) => { d.expiresAt = '2026-11-11T00:00:00.000Z'; },
    (d) => { d.authority = 'undelegated'; },
    (d) => { d.reason = ''; },
    (d) => { d.extra = 'unrecognised'; },
  ]) {
    const input = fixture(); change(input.decisions.decisions[0]); await assert.rejects(compilePublication(input));
  }
});

test('renewing a feed increments revision and cannot renew its decisions or evidence', async () => {
  const input = fixture(); const renewed = await compilePublication(await next(input));
  assert.equal(JSON.parse(renewed.body).revision, 3);
  assert.equal(JSON.parse(renewed.body).providers[0].reviewExpiresAt, EXPIRY);
  const expired = await compilePublication(await next(input, { now: Date.parse(EXPIRY) }));
  assert.deepEqual(JSON.parse(expired.body).providers, []);
  await assert.rejects(compilePublication({ ...input, now: Date.parse(EXPIRY) }), /initial activation/);
});

test('release validity is bounded at 24 hours without clipping or extending review expiry', async () => {
  for (const lifetimeHours of [0, 25, 1.5, '12']) {
    const input = fixture(); input.adoption.publication.lifetimeHours = lifetimeHours;
    await assert.rejects(compilePublication(input), /lifetime/);
  }
  const input = fixture(); input.adoption.publication.lifetimeHours = 24;
  const p = await compilePublication(input); assert.equal(Date.parse(p.state.expiresAt) - NOW, 24 * 3600000);
  const soon = fixture(); const d = soon.decisions.decisions[0]; d.expiresAt = '2026-11-08T12:01:00.000Z';
  const p2 = await compilePublication(soon); assert.equal(JSON.parse(p2.body).providers[0].reviewExpiresAt, d.expiresAt);
  const policy = new TrustedProviderPolicy({ url: FEED_URL, now: () => NOW + 60000, fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body: p2.body }) });
  await assert.rejects(policy.assertAccepted(d.issuer, `a@${d.handleDomains[0]}`), { code: 'issuer_not_accepted' });
});

test('suspension and withdrawal remove authority; renewal cannot silently reinstate it', async () => {
  for (const action of ['suspend', 'withdraw']) {
    const input = await next(fixture());
    input.decisions.decisions.push(administrativeDecision(input.decisions.decisions[0], action));
    const p = await compilePublication(input); assert.deepEqual(JSON.parse(p.body).providers, []);
    const renew = structuredClone(input.decisions.decisions[0]);
    Object.assign(renew, { id: 'bad-renewal', action: 'renew', decidedAt: '2026-11-08T12:02:00.000Z', supersedes: input.decisions.decisions[1].id });
    input.decisions.decisions.push(renew); input.now += 60000;
    await assert.rejects(compilePublication(input), /requires reinstatement/);
    renew.action = 'reinstate';
    const restored = await compilePublication(input); assert.equal(JSON.parse(restored.body).providers.length, 1);
  }
});

test('append-only decision digests reject lost suspensions, edits, and reordered history', async () => {
  const input = await next(fixture());
  input.decisions.decisions.push(administrativeDecision(input.decisions.decisions[0]));
  const suspended = await next(input);
  const lost = { ...suspended, decisions: structuredClone(suspended.decisions) }; lost.decisions.decisions.pop();
  await assert.rejects(compilePublication(lost), /history changed/);
  const edited = { ...suspended, decisions: structuredClone(suspended.decisions) }; edited.decisions.decisions[0].reason = 'Restored before reviewed changes';
  await assert.rejects(compilePublication(edited), /history changed/);
  const reordered = { ...suspended, decisions: structuredClone(suspended.decisions) }; reordered.decisions.decisions.reverse();
  await assert.rejects(compilePublication(reordered));
});

test('authenticated decision sequence and immutable adoption cannot be bypassed', async () => {
  const input = await next(fixture()); input.adoption.delegates.push('new-authority');
  await assert.rejects(compilePublication(input), /adopted policy changed/);
  for (const change of [
    (i) => { i.decisions.decisions[0].supersedes = 'invented'; },
    (i) => { i.decisions.decisions[0].action = 'reinstate'; },
    (i) => { i.adoption.status = 'draft'; },
    (i) => { i.adoption.publication.url = 'https://other.example/list'; },
    (i) => { i.pagesCommit = 'c'.repeat(40); },
    (i) => { i.previousFeed = encode({ ...JSON.parse(i.previousFeed), revision: 2 }); },
  ]) { const i = fixture(); change(i); await assert.rejects(compilePublication(i)); }
});

test('publication clock, invalid dates, digest mismatch and malformed wire scope fail closed', async () => {
  const input = await next(fixture(), { now: NOW - 1 });
  await assert.rejects(compilePublication(input), /clock moved backwards/);
  for (const change of [
    (d) => { d.expiresAt = '2026-11-31T00:00:00.000Z'; },
    (d) => { d.handleDomains = ['MAIL.provider.example']; },
    (d) => { d.issuer = 'https://identity.provider.example/'; },
    (d) => { d.issuer = 'https://identity.provider.example?x=1'; },
    (d) => { d.reviewUrl = 'http://programme.example'; },
    (d) => { d.specRevision = 'latest'; },
  ]) { const i = fixture(); change(i.decisions.decisions[0]); await assert.rejects(compilePublication(i)); }
  const p = await compilePublication(fixture()); p.state.revision++;
  assert.throws(() => validateState(p.state, p.body), /disagree/);
});

test('two admissions cannot share a handle domain and exceed SDK bounds', async () => {
  const input = fixture(); const second = structuredClone(input.decisions.decisions[0]);
  second.id = 'other-admission'; second.issuer = 'https://other-provider.example'; input.decisions.decisions.push(second);
  await assert.rejects(compilePublication(input), (e) => e.code === 'issuer_policy_unavailable' && /duplicate handle domain/.test(e.cause.message));
});
