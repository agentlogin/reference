import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { z } from 'zod';
import { identifier } from './config.js';

function httpsUrl(value: string): URL | undefined {
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' || !/^https:\/\/[^/?#]+(?:[/?#]|$)/i.test(value) || u.username || u.password || value.includes('#') || /[\\\x00-\x20\x7f]/.test(value) || /^https:\/\/[^/?#]*@/i.test(value)) return;
    return u;
  } catch { return; }
}
// z.string().url() trims inputs; identifiers here must retain exact string identity.
const https = z.string().refine((value) => Boolean(httpsUrl(value)), 'Use HTTPS without credentials or a fragment').meta({ format: 'uri' });
const issuerIdentifier = https.refine((value) => !value.includes('?'), 'Issuer identifiers cannot contain a query');
const openClientId = https.refine((value) => {
  const u = httpsUrl(value);
  const path = /^https:\/\/[^/?#]+(\/[^?#]*)/i.exec(value)?.[1];
  return Boolean(u && !isIP(u.hostname.replace(/^\[|\]$/g, '')) && path &&
    !path.split('/').some((segment) => /^(?:\.|%2e){1,2}$/i.test(segment)));
}, 'Use a Client ID Metadata Document URL with a domain and a path, without dot path segments');
const instant = z.string().datetime({ offset: true });
const evidence = z.object({
  kind: z.enum(['domain_control', 'protocol_test', 'independent_interop', 'operational_review']),
  url: https,
  observedAt: instant,
  expiresAt: instant,
  reviewer: z.string().min(1).max(200),
  revision: z.string().regex(/^[a-f0-9]{40}$/),
}).strict().refine((e) => Date.parse(e.observedAt) < Date.parse(e.expiresAt), 'Evidence expiry must follow observation');
const common = {
  id: identifier,
  name: z.string().min(1).max(128),
  operator: z.string().min(1).max(200),
  homepage: https,
  status: z.enum(['candidate', 'reviewed', 'suspended']),
  specRevision: z.string().regex(/^[a-f0-9]{40}$/),
  evidence: z.array(evidence).max(20),
  updatedAt: instant,
};
const provider = z.object({ ...common, kind: z.literal('provider'), issuer: issuerIdentifier, handleDomains: z.array(z.string().regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/)).min(1).max(128) }).strict();
const applicationFields = { ...common, kind: z.literal('application'), initiateLoginUri: https };
const openApplication = z.object({ ...applicationFields, clientType: z.literal('open').default('open'), clientId: openClientId }).strict();
const registeredApplication = z.object({
  ...applicationFields,
  clientType: z.literal('registered'),
  clientId: z.string().min(1).max(2048).regex(/^[\x20-\x7e]+$/, 'Use the exact opaque registered client identifier'),
  issuer: issuerIdentifier,
}).strict();
export const CatalogSchema = z.object({
  version: z.literal(1),
  kind: z.enum(['providers', 'applications']),
  updatedAt: instant,
  entries: z.array(z.union([provider, openApplication, registeredApplication])).max(10_000),
}).strict().superRefine((c, ctx) => {
  const ids = new Set<string>();
  const subjects = new Set<string>();
  for (const [index, e] of c.entries.entries()) {
    const issue = (message: string) => ctx.addIssue({ code: 'custom', path: ['entries', index], message });
    if ((c.kind === 'providers') !== (e.kind === 'provider')) issue('Catalog kind does not match entry');
    const subject = e.kind === 'provider' ? JSON.stringify(['provider', e.issuer])
      : e.clientType === 'registered' ? JSON.stringify(['registered', e.issuer, e.clientId])
      : JSON.stringify(['open', e.clientId]);
    if (ids.has(e.id) || subjects.has(subject)) issue('Duplicate identifier or subject');
    ids.add(e.id); subjects.add(subject);
    if (e.evidence.some((v) => v.revision !== e.specRevision)) issue('Evidence must refer to the listed specification revision');
    if (e.status === 'reviewed' && !['domain_control', 'protocol_test'].every((kind) => e.evidence.some((v) => v.kind === kind))) issue('Reviewed entries require domain-control and protocol-test evidence');
  }
});
export type Catalog = z.infer<typeof CatalogSchema>;

/** Editor schema; protocol URL and cross-record checks remain in CatalogSchema. */
export function catalogJsonSchema() {
  return z.toJSONSchema(CatalogSchema, { io: 'input' });
}

export function readCatalog(file: string): Catalog {
  const data = readFileSync(file);
  if (data.length > 2 * 1024 * 1024) throw new Error('Catalog exceeds 2 MiB');
  return CatalogSchema.parse(JSON.parse(data.toString('utf8')));
}

/** Listings are information, never automatic enrollment, endpoint pinning or issuer acceptance. */
export function catalogView(catalogs: Catalog[], now = Date.now()) {
  return catalogs.flatMap((catalog) => catalog.entries.map((entry) => ({
    ...entry,
    effectiveStatus: entry.status === 'reviewed' && entry.evidence.some((e) => Date.parse(e.observedAt) > now || Date.parse(e.expiresAt) <= now) ? 'review_expired' : entry.status,
    automaticTrust: false,
  })));
}
