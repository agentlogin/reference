// Private files (keys, cookies): directory 0700, file 0600, written atomically, never through a symbolic link.
import { closeSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
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

/**
 * Writes `value` to `path` atomically (temporary file, then rename). `guard`, when given, runs immediately before the
 * rename and may throw to abandon the write. This check is defense in depth; mutual exclusion is provided by
 * withFileLock, which never evicts a live writer.
 */
export function writePrivateJson(path: string, value: unknown, guard?: () => void): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ds = lstatSync(dir);
  if (!ds.isDirectory() || (uid !== undefined && (ds.uid !== uid || (ds.mode & 0o077) !== 0))) throw new Error(`${dir} must be a directory owned by you with mode 0700`);
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error(`${path} is a symbolic link; refusing to write through it`);
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const fd = openSync(tmp, 'wx', 0o600); // exclusive create: never follows an existing link
  try {
    try {
      writeSync(fd, JSON.stringify(value, null, 1));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    guard?.();
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* gone already */ }
    throw e;
  }
}

const LOCK_WAIT_MS = 60_000;

function readLock(lock: string): string | undefined {
  try {
    return readFileSync(lock, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw e;
  }
}
/** Unknown/malformed owners and reused PIDs fail closed. Only ESRCH proves a local process cannot resume. */
function holderIsDead(content: string): boolean {
  const owner = /^([1-9]\d*):[a-zA-Z0-9-]+$/.exec(content);
  if (!owner) return false;
  const pid = Number(owner[1]);
  if (!Number.isSafeInteger(pid) || pid > 0x7fffffff) return false;
  try {
    process.kill(pid, 0);
    return false;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ESRCH';
  }
}
/** Publish a complete owner token atomically: a crash cannot leave a newly acquired lock with an empty owner. */
function createLock(lock: string, token: string): void {
  const candidate = `${lock}.${token.replace(':', '.')}.owner`;
  const fd = openSync(candidate, 'wx', 0o600);
  try {
    try {
      writeSync(fd, token);
    } finally {
      closeSync(fd);
    }
    linkSync(candidate, lock); // exclusive, atomic link; the candidate and lock are on the same local file system
  } finally {
    unlinkSync(candidate);
  }
}
/**
 * Serialize recovery and check identity again inside that critical section. The recovery lock is never stolen:
 * if a process dies in this tiny section, subsequent writers fail closed until an operator stops all writers
 * and removes the abandoned .takeover file. Recovering that lock with another check/unlink would recreate the race.
 */
function breakDeadLock(lock: string, deadContent: string): void {
  const breaker = `${lock}.takeover`;
  try {
    closeSync(openSync(breaker, 'wx', 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    return;
  }
  try {
    const current = readLock(lock);
    if (current === deadContent && holderIsDead(current)) unlinkSync(lock);
  } finally {
    unlinkSync(breaker);
  }
}

/**
 * Runs `fn` with an exclusive local-file-system lock, shared by processes on the same host/PID namespace.
 * A live process never loses ownership, even if it is suspended between a guard check and the final rename.
 * Age/heartbeats cannot establish that a writer is dead and are deliberately not used as fencing.
 * Dead process locks are recovered; hung/live processes, unknown owners and PID reuse cause a bounded failure.
 * All writers must use this protocol; do not manually remove locks while any writer can still resume.
 */
export async function withFileLock<T>(path: string, fn: (guard: () => void) => T | Promise<T>): Promise<T> {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ds = lstatSync(dir);
  if (!ds.isDirectory() || (uid !== undefined && (ds.uid !== uid || (ds.mode & 0o077) !== 0))) throw new Error(`${dir} must be a directory owned by you with mode 0700`);
  const lock = `${path}.lock`;
  const token = `${process.pid}:${randomBytes(12).toString('hex')}`;
  const deadline = performance.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      createLock(lock, token);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    if (performance.now() >= deadline) throw new Error(`could not lock ${path}: another process holds ${lock}, or lock recovery requires manual cleanup`);
    const seen = readLock(lock);
    if (seen && holderIsDead(seen)) breakDeadLock(lock, seen);
    await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 25)));
  }
  const holds = (): boolean => readLock(lock) === token;
  try {
    return await fn(() => {
      if (!holds()) throw new Error(`lost the lock on ${path}: lock files were modified externally; nothing was written`);
    });
  } finally {
    if (holds()) unlinkSync(lock);
  }
}
