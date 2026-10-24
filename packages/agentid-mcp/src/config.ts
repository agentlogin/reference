import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { z } from 'zod';

export const identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);
export const uuid = z.string().uuid();
export const ConfigSchema = z.object({
  version: z.literal(1),
  inbox: z.string().min(3).max(254).regex(/^[^@\s/\\?#\x00-\x1f\x7f]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+$/),
  credentialEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/),
  applications: z.record(identifier, z.object({
    appId: uuid.transform((value) => value.toLowerCase()),
    name: z.string().min(1).max(128).regex(/^[^\x00-\x1f\x7f]+$/),
    origin: z.string().refine((value) => {
      try { const u = new URL(value); return value === u.origin && u.protocol === 'https:' && !u.username && !u.password; } catch { return false; }
    }, 'Use a canonical HTTPS application origin'),
  }).strict()).refine((apps) => Object.keys(apps).length <= 64 && new Set(Object.values(apps).map((a) => a.appId)).size === Object.keys(apps).length),
}).strict();
export type Config = z.infer<typeof ConfigSchema>;

export function readConfig(file: string): Config {
  if (!isAbsolute(file)) throw new Error('Use an absolute config path');
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 64 * 1024 || (typeof process.getuid === 'function' && (st.uid !== process.getuid() || (st.mode & 0o077) !== 0))) throw new Error('Use a private regular config file');
    return ConfigSchema.parse(JSON.parse(readFileSync(fd, 'utf8')));
  } finally { closeSync(fd); }
}
