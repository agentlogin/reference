// Private files (keys, cookies): directory 0700, file 0600, written atomically, never through a symbolic link.
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
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

const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 20_000;

/**
 * Runs `fn` while holding an exclusive lock on `path`, across processes. Atomic replacement alone does not protect a
 * read-modify-write: two processes that read the same old content each write back their own version and one is lost.
 * The lock is a file created with O_EXCL; one left behind by a process that died is taken over after 30 s.
 */
export async function withFileLock<T>(path: string, fn: () => T | Promise<T>): Promise<T> {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lock = `${path}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lock, 'wx', 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      try {
        if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) unlinkSync(lock);
      } catch {
        // the holder released it in between
      }
      if (Date.now() > deadline) throw new Error(`could not lock ${path}: another process holds ${lock}`);
      await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 25)));
    }
  }
  try {
    return await fn();
  } finally {
    try {
      unlinkSync(lock);
    } catch {
      // already gone
    }
  }
}
