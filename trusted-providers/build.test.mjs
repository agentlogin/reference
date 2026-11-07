import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { TrustedProviderPolicy } from '@agentlogin/rp';
import { prepareDraftPublication, writeDraftPublication } from './build.mjs';

const original = readFileSync(new URL('./v1.json', import.meta.url));
const draft = () => JSON.parse(original);
const encode = (value) => Buffer.from(JSON.stringify(value));

test('draft publication preserves exact bytes, original dates and explicit non-operational status', async () => {
  const publication = await prepareDraftPublication(original);
  assert.deepEqual(publication.body, original);
  assert.match(publication.html, /Draft programme\. No approved providers\./);
  assert.match(publication.html, /programme is not operational/);
  assert.match(publication.html, /Reviews and decisions may be automated under published delegation/);
  assert.match(publication.html, /no human approval or reviewer quorum is required/);
  assert.match(publication.html, /Automated or affiliated review does not establish independent endorsement/);
  assert.ok(publication.html.includes(draft().issuedAt));
  assert.ok(publication.html.includes(draft().expiresAt));
  assert.match(publication.html, /Rebuilding this page never renews it/);
  assert.deepEqual(await prepareDraftPublication(original), publication);
  const directory = mkdtempSync(join(tmpdir(), 'agentlogin-draft-publication-'));
  try {
    writeDraftPublication(directory, publication);
    assert.deepEqual(readdirSync(join(directory, 'trusted-providers')).sort(), ['index.html', 'v1.json']);
    assert.deepEqual(readFileSync(join(directory, 'trusted-providers/v1.json')), original);
    assert.equal(readFileSync(join(directory, 'trusted-providers/index.html'), 'utf8'), publication.html);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('draft publisher refuses activation, including an empty active feed', async () => {
  const active = { ...draft(), status: 'active' };
  await assert.rejects(prepareDraftPublication(encode(active)), /only an empty draft/);
  active.providers = [{ issuer: 'https://identity.sentfrom.ai' }];
  await assert.rejects(prepareDraftPublication(encode(active)), /only an empty draft/);
  await assert.rejects(prepareDraftPublication(encode({ ...draft(), providers: active.providers })), /only an empty draft/);
});

test('draft publisher uses the SDK wire validation rather than accepting malformed fail-closed feeds', async () => {
  for (const changes of [
    { version: 2 }, { programme: 'other-programme' }, { profile: 'other-profile' },
    { revision: 0 }, { revision: Number.MAX_SAFE_INTEGER + 1 }, { extra: 'unrecognised' },
    { issuedAt: '2026-02-30T00:00:00.000Z' }, { expiresAt: '2026-11-09T00:00:00.000Z' },
    { expiresAt: draft().issuedAt }, { issuedAt: null },
  ]) {
    await assert.rejects(prepareDraftPublication(encode({ ...draft(), ...changes })), /SDK validation/, JSON.stringify(changes));
  }
  await assert.rejects(prepareDraftPublication(Buffer.from('{')));
  await assert.rejects(prepareDraftPublication(Buffer.from([0xff, 0xfe])));
  await assert.rejects(prepareDraftPublication(Buffer.alloc(64 * 1024 + 1)), /too large/);
});

test('published draft cannot admit a directory candidate at issuance or after expiry', async () => {
  const { body } = await prepareDraftPublication(original);
  for (const now of [Date.parse(draft().issuedAt) + 1, Date.parse(draft().expiresAt) + 1]) {
    const policy = new TrustedProviderPolicy({
      url: 'https://agentlogin.github.io/reference/trusted-providers/v1.json', now: () => now,
      fetch: async (url) => ({ url, status: 200, headers: {}, redirects: [], body }),
    });
    await assert.rejects(policy.assertAccepted('https://identity.sentfrom.ai', 'agent@mail.sentfrom.ai'), (error) => {
      assert.equal(error.code, 'issuer_policy_unavailable');
      assert.equal(error.status, 503);
      assert.equal(error.cause.message, now < Date.parse(draft().expiresAt) ? 'policy is not active' : 'policy is not current');
      return true;
    });
  }
});

test('catalog build validates before replacing its artifact and includes only the historical draft', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentlogin-catalog-build-'));
  const repository = fileURLToPath(new URL('../', import.meta.url));
  try {
    for (const folder of ['catalogs/dist', 'trusted-providers']) mkdirSync(join(directory, folder), { recursive: true });
    symlinkSync(join(repository, 'node_modules'), join(directory, 'node_modules'), 'dir');
    for (const file of ['catalogs/build.mjs', 'catalogs/providers.json', 'catalogs/applications.json', 'trusted-providers/build.mjs', 'trusted-providers/v1.json']) {
      copyFileSync(join(repository, file), join(directory, file));
    }
    const sentinel = join(directory, 'catalogs/dist/obsolete.html');
    writeFileSync(sentinel, 'old generated artifact');
    writeFileSync(join(directory, 'trusted-providers/v1.json'), encode({ ...draft(), status: 'active' }));
    assert.throws(() => execFileSync(process.execPath, ['catalogs/build.mjs'], { cwd: directory, stdio: 'pipe' }));
    assert.equal(readFileSync(sentinel, 'utf8'), 'old generated artifact');
    writeFileSync(join(directory, 'trusted-providers/v1.json'), original);
    execFileSync(process.execPath, ['catalogs/build.mjs'], { cwd: directory, stdio: 'pipe' });
    assert.equal(existsSync(sentinel), false);
    assert.deepEqual(readFileSync(join(directory, 'catalogs/dist/trusted-providers/v1.json')), original);
    assert.match(readFileSync(join(directory, 'catalogs/dist/index.html'), 'utf8'), /trusted-providers\//);
    assert.match(readFileSync(join(directory, 'catalogs/dist/trusted-providers/index.html'), 'utf8'), /No approved providers/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
