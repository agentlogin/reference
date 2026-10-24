import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseHandle } from 'agentlogin';
import { z } from 'zod';

export const identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);
const text = z.string().min(1).max(256).refine((s) => !/[\x00-\x1f\x7f]/.test(s));
const path = z.string().max(2048).refine((s) => s.startsWith('/') && !s.startsWith('//') && !/[\\#\x00-\x20]/.test(s), 'Use an absolute path without a fragment');
const pointer = z.string().max(256).regex(/^(?:\/(?:[^~\/]|~[01])*)+$/);
const operation = z.object({
  description: text,
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  path,
  inputFields: z.array(identifier).max(32).default([]),
  queryFields: z.array(identifier).max(32).refine((fields) => new Set(fields).size === fields.length, 'Query fields must be unique').optional(),
  output: z.record(identifier, pointer).default({}),
}).strict();

export const ConfigSchema = z.object({
  version: z.literal(1),
  stateDirectory: z.string().refine(isAbsolute, 'Use an absolute state directory'),
  developmentLoopback: z.boolean().default(false),
  signInTimeoutSeconds: z.number().int().min(10).max(600).default(180),
  identities: z.record(identifier, z.object({
    handle: z.string().refine((s) => parseHandle(s)?.handle === s, 'Use a canonical Agent Handle'),
    issuer: z.string().optional(),
    ownerPortal: z.string().optional(),
    ownerApprovalPath: z.string().max(2048).refine((s) => s.startsWith('/') && !s.startsWith('//') && !/[\\?#\x00-\x20]/.test(s) && s.split('{transaction_id}').length === 2 && !/[{}]/.test(s.replace('{transaction_id}', '')), 'Use one {transaction_id} placeholder in an absolute path').optional(),
    enrollmentEndpoint: z.string().optional(),
    enrollmentCredentialEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/).optional(),
  }).strict()).refine((v) => Object.keys(v).length > 0 && Object.keys(v).length <= 32),
  applications: z.record(identifier, z.object({
    name: text,
    origin: z.string(),
    loginPath: path,
    sessionCheck: z.object({ path, handlePointer: pointer, issuerPointer: pointer, subjectPointer: pointer }).strict(),
    logoutPath: path.optional(),
    operations: z.record(identifier, operation).default({}),
  }).strict()).refine((v) => Object.keys(v).length <= 64),
  catalogFiles: z.array(z.string().refine(isAbsolute)).max(8).default([]),
}).strict();
export type Config = z.infer<typeof ConfigSchema>;
export type Application = Config['applications'][string];
export type Identity = Config['identities'][string];

export function checkedUrl(value: string, developmentLoopback = false): URL {
  const url = new URL(value);
  const local = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(developmentLoopback && local && url.protocol === 'http:'))) throw new Error('Invalid configured URL');
  return url;
}

export function parseConfig(value: unknown): Config {
  const config = ConfigSchema.parse(value);
  for (const identity of Object.values(config.identities)) {
    if (identity.ownerApprovalPath && !identity.ownerPortal) throw new Error('An Owner approval path requires an Owner portal');
    for (const value of [identity.issuer, identity.ownerPortal, identity.enrollmentEndpoint]) {
      if (value) {
        const url = checkedUrl(value, config.developmentLoopback);
        if (url.search) throw new Error('Identity URLs cannot contain query parameters');
      }
    }
  }
  for (const app of Object.values(config.applications)) {
    const origin = checkedUrl(app.origin, config.developmentLoopback);
    if (app.origin !== origin.origin) throw new Error('Application origin must be a canonical origin');
    for (const p of [app.loginPath, app.sessionCheck.path, app.logoutPath, ...Object.values(app.operations).map((op) => op.path)]) {
      if (p && checkedUrl(new URL(p, origin).href, config.developmentLoopback).origin !== app.origin) throw new Error('Application paths must remain on their configured origin');
    }
    for (const op of Object.values(app.operations)) {
      if (op.method === 'GET' && op.inputFields.length) throw new Error('GET operations do not accept a body');
      if (op.method !== 'GET' && op.queryFields !== undefined) throw new Error('Only GET operations accept query fields');
      const fixedQuery = new URL(op.path, origin).searchParams;
      if (op.queryFields?.some((field) => fixedQuery.has(field))) throw new Error('Query fields cannot replace configured query parameters');
      if (Object.keys(op.output).some(sensitiveName) || Object.values(op.output).some((p) => p.split('/').some(sensitiveName))) throw new Error('Credentials cannot be selected as operation output');
    }
  }
  return config;
}

export const sensitiveName = (name: string): boolean => /(?:token|secret|password|authorization|cookie|assertion|challenge|private.?jwk|private.?key|redirect.?url|continue.?url)/i.test(name);

/** Open first and inspect the descriptor, so replacement with a symbolic link cannot race validation. */
export function readPrivateConfig(file: string): Config {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 128 * 1024 || (typeof process.getuid === 'function' && (st.uid !== process.getuid() || (st.mode & 0o077) !== 0))) throw new Error('Configuration must be a regular file owned by you, mode 0600, at most 128 KiB');
    return parseConfig(JSON.parse(readFileSync(fd, 'utf8')));
  } finally { closeSync(fd); }
}

export function atPointer(value: unknown, pointer: string): unknown {
  let current = value;
  for (const part of pointer.slice(1).split('/').map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    if (current === null || typeof current !== 'object' || !Object.hasOwn(current, part)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
