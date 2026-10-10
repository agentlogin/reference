// Private files (keys, cookies): directory 0700, file 0600, written atomically, never through a symbolic link.
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;

export function readPrivateJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  const st = lstatSync(path);
  if (st.isSymbolicLink()) throw new Error(`${path} is a symbolic link; refusing to read it`);
  if (uid !== undefined && (st.uid !== uid || (st.mode & 0o077) !== 0)) throw new Error(`${path} must be owned by you and readable by you only (chmod 600)`);
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

export function writePrivateJson(path: string, value: unknown): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ds = lstatSync(dir);
  if (!ds.isDirectory() || (uid !== undefined && (ds.uid !== uid || (ds.mode & 0o077) !== 0))) throw new Error(`${dir} must be a directory owned by you with mode 0700`);
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error(`${path} is a symbolic link; refusing to write through it`);
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const fd = openSync(tmp, 'wx', 0o600); // exclusive create: never follows an existing link
  try {
    writeSync(fd, JSON.stringify(value, null, 1));
    fsyncSync(fd);
  } catch (e) {
    closeSync(fd);
    unlinkSync(tmp);
    throw e;
  }
  closeSync(fd);
  renameSync(tmp, path);
}
