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
