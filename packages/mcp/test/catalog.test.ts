import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CatalogSchema, catalogJsonSchema, catalogView } from '../src/catalog.js';

const common = {
  kind: 'application', id: 'example', name: 'Example', operator: 'Example',
  homepage: 'https://app.example/', initiateLoginUri: 'https://app.example/login',
  status: 'candidate', specRevision: 'a'.repeat(40), evidence: [], updatedAt: '2026-10-15T00:00:00Z',
};
const catalog = (...entries: unknown[]) => ({ version: 1, kind: 'applications', updatedAt: common.updatedAt, entries });
const open = { ...common, clientId: 'https://app.example/client.json' };
const registered = { ...common, clientType: 'registered', clientId: 's6BhdRkqt3', issuer: 'https://issuer.example/tenant' };
const coreProvider = {
  kind: 'provider', id: 'core', name: 'Core provider', operator: 'Example',
  homepage: 'https://issuer.example', issuer: 'https://issuer.example', handleDomains: ['example.com'],
  status: 'candidate', specRevision: common.specRevision, evidence: [], updatedAt: common.updatedAt,
};
const agentIdProvider = {
  kind: 'provider', protocol: 'agentid', id: 'agentid', name: 'AgentID by AgentMail', operator: 'AgentMail, Inc.',
  homepage: 'https://www.agentid.com', issuer: 'https://auth.agentid.com', handleDomains: ['agentmail.to'],
  status: 'candidate', protocolReference: 'https://docs.agentmail.to/agentid-sign-in',
  evidence: [], updatedAt: common.updatedAt,
};
const providers = (...entries: unknown[]) => ({ ...catalog(...entries), kind: 'providers' });
const evidenceFields = {
  url: 'https://reviewer.example/report', observedAt: '2026-10-14T00:00:00Z',
  expiresAt: '2026-11-14T00:00:00Z', reviewer: 'Example reviewer',
};

test('application catalogs distinguish open clients and issuer-scoped registered clients', () => {
  const parsed = CatalogSchema.parse(catalog(open, { ...registered, id: 'registered' }));
  assert.equal(parsed.entries[0]?.kind === 'application' && parsed.entries[0].clientType, 'open');
  assert.deepEqual(parsed.entries[1], { ...registered, id: 'registered' });
  assert.equal(CatalogSchema.safeParse(catalog({ ...registered, issuer: undefined })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog({ ...registered, clientType: undefined })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog({ ...open, issuer: registered.issuer })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog({ ...registered, clientId: '' })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog({ ...registered, clientId: 'id\nother' })).success, false);
  assert.equal(catalogView([parsed]).every((entry) => entry.automaticTrust === false), true);
});

test('duplicate registered identities use the exact issuer and opaque client identifier', () => {
  assert.equal(CatalogSchema.safeParse(catalog(registered, { ...registered, id: 'second' })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog(registered, { ...registered, id: 'second', issuer: 'https://other.example/tenant' })).success, true);
  assert.equal(CatalogSchema.safeParse(catalog(registered, { ...registered, id: 'second', issuer: `${registered.issuer}/` })).success, true);
  assert.equal(CatalogSchema.safeParse(catalog(open, { ...open, id: 'second', clientType: 'open' })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog(open, { ...open, id: 'second', clientId: 'https://app.example:443/client.json' })).success, true);
  assert.equal(CatalogSchema.safeParse(catalog(open, { ...registered, id: 'registered', clientId: open.clientId })).success, true);
});

test('catalog URL checks fail closed without throwing and preserve exact identifiers', () => {
  for (const issuer of ['not-a-url', 'http://issuer.example', 'https:issuer.example', 'https:///issuer.example', 'https://user@issuer.example', 'https://@issuer.example', 'https://issuer.example?x=1', 'https://issuer.example?', 'https://issuer.example#', 'https://issuer.example/\n']) {
    assert.equal(CatalogSchema.safeParse(catalog({ ...registered, issuer })).success, false, issuer);
  }
  for (const clientId of ['not-a-url', 'https://app.example', 'https://127.0.0.1/client.json', 'https://[::1]/client.json', 'https://app.example/./client.json', 'https://app.example/a/../client.json', 'https://app.example/a/%2e%2e/client.json', 'https://app.example/client.json#']) {
    assert.equal(CatalogSchema.safeParse(catalog({ ...open, clientId })).success, false, clientId);
  }
  const clientId = 'https://app.example:443/client.json?version=1';
  const parsed = CatalogSchema.parse(catalog({ ...open, clientId }));
  assert.equal(parsed.entries[0]?.kind === 'application' && parsed.entries[0].clientId, clientId);
});

test('provider issuer identifiers reject query components without normalizing valid identifiers', () => {
  const provider = {
    kind: 'provider', id: 'provider', name: 'Provider', operator: 'Provider',
    homepage: 'https://issuer.example/', status: 'candidate', specRevision: common.specRevision,
    evidence: [], updatedAt: common.updatedAt, handleDomains: ['example.com'],
  };
  const listing = (issuer: string) => ({
    version: 1, kind: 'providers', updatedAt: common.updatedAt, entries: [{ ...provider, issuer }],
  });
  for (const issuer of ['https://issuer.example?tenant=one', 'https://issuer.example?', 'https://issuer.example/tenant?']) {
    assert.equal(CatalogSchema.safeParse(listing(issuer)).success, false, issuer);
  }
  const issuer = 'https://issuer.example:443/tenant/';
  const parsed = CatalogSchema.parse(listing(issuer));
  assert.equal(parsed.entries[0]?.kind === 'provider' && parsed.entries[0].issuer, issuer);
});

test('editor schema retains both application forms and the legacy open-client default', () => {
  const schema = catalogJsonSchema() as any;
  const variants = schema.properties.entries.items.anyOf;
  const applications = variants.filter((variant: any) => variant.properties.kind.const === 'application');
  assert.equal(applications.length, 2);
  const openSchema = applications.find((variant: any) => variant.properties.clientType.const === 'open');
  const registeredSchema = applications.find((variant: any) => variant.properties.clientType.const === 'registered');
  assert.equal(openSchema.properties.clientType.default, 'open');
  assert.equal(openSchema.required.includes('clientType'), false);
  assert.equal(registeredSchema.required.includes('clientType'), true);
  assert.equal(registeredSchema.required.includes('issuer'), true);
});

test('catalogs distinguish AgentID integration from legacy and explicit Agent Login Core providers', () => {
  const parsed = CatalogSchema.parse(providers(coreProvider, agentIdProvider));
  assert.deepEqual(parsed.entries, [coreProvider, agentIdProvider]);
  const view = catalogView([parsed]);
  assert.deepEqual(view.map((entry) => entry.protocol), ['agent-login', 'agentid']);
  assert.equal(view.every((entry) => entry.automaticTrust === false && entry.effectiveStatus === 'candidate'), true);
  assert.equal('specRevision' in view[1]!, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...coreProvider, protocol: 'agent-login' })).success, true);
  assert.equal(CatalogSchema.safeParse(providers({ ...agentIdProvider, specRevision: common.specRevision })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...agentIdProvider, protocol: undefined })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...agentIdProvider, protocolReference: undefined })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...agentIdProvider, protocolReference: 'http://docs.example' })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...coreProvider, protocol: 'agentid' })).success, false);
  assert.equal(CatalogSchema.safeParse(catalog(agentIdProvider)).success, false);
  assert.equal(CatalogSchema.safeParse(catalog({ ...open, protocol: 'agentid' })).success, false);
  // An issuer cannot acquire a second listing just by changing its protocol label.
  assert.equal(CatalogSchema.safeParse(providers(coreProvider, { ...agentIdProvider, issuer: coreProvider.issuer })).success, false);
});

test('reviewed AgentID listings require explicitly matching AgentID evidence, never Core revision evidence', () => {
  const agentIdEvidence = ['domain_control', 'protocol_test'].map((kind) => ({
    ...evidenceFields, kind, protocol: 'agentid', reference: agentIdProvider.protocolReference,
  }));
  const coreEvidence = ['domain_control', 'protocol_test'].map((kind) => ({
    ...evidenceFields, kind, revision: common.specRevision,
  }));
  const reviewed = { ...agentIdProvider, status: 'reviewed', evidence: agentIdEvidence };
  const parsed = CatalogSchema.parse(providers(reviewed));
  assert.equal(catalogView([parsed], Date.parse(common.updatedAt))[0]?.effectiveStatus, 'reviewed');
  assert.equal(catalogView([parsed], Date.parse('2026-12-01T00:00:00Z'))[0]?.effectiveStatus, 'review_expired');
  assert.equal(catalogView([parsed], Date.parse('2026-10-01T00:00:00Z'))[0]?.effectiveStatus, 'review_expired');
  assert.equal(CatalogSchema.safeParse(providers({ ...reviewed, evidence: [] })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...reviewed, evidence: agentIdEvidence.slice(0, 1) })).success, false);
  assert.equal(CatalogSchema.safeParse(providers({ ...reviewed, evidence: coreEvidence })).success, false);
  for (const change of [
    { protocol: 'agent-login' }, { protocol: undefined }, { reference: 'https://docs.example/other' },
    { revision: common.specRevision }, { expiresAt: evidenceFields.observedAt },
  ]) {
    assert.equal(CatalogSchema.safeParse(providers({ ...reviewed, evidence: agentIdEvidence.map((e) => ({ ...e, ...change })) })).success, false);
  }
  assert.equal(CatalogSchema.safeParse(providers({ ...coreProvider, status: 'reviewed', evidence: coreEvidence })).success, true);
  assert.equal(CatalogSchema.safeParse(providers({ ...coreProvider, status: 'reviewed', evidence: agentIdEvidence })).success, false);
});

test('editor schema makes AgentID protocol and reference explicit without a Core specification revision', () => {
  const schema = catalogJsonSchema() as any;
  const variants = schema.properties.entries.items.anyOf;
  const core = variants.find((variant: any) => variant.properties.kind.const === 'provider' && variant.properties.protocol.const === 'agent-login');
  const agentid = variants.find((variant: any) => variant.properties.protocol.const === 'agentid');
  assert.equal(core.required.includes('protocol'), false);
  assert.equal(core.required.includes('specRevision'), true);
  assert.equal(agentid.required.includes('protocol'), true);
  assert.equal(agentid.required.includes('protocolReference'), true);
  assert.equal('specRevision' in agentid.properties, false);
  assert.equal(agentid.properties.evidence.items.required.includes('protocol'), true);
  assert.equal(agentid.properties.evidence.items.required.includes('reference'), true);
  assert.equal('revision' in agentid.properties.evidence.items.properties, false);
});
