// Private files (keys, cookies): directory 0700, file 0600, written atomically, never through a symbolic link.
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, utimesSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
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
 * rename and may throw to abandon the write: a writer that has lost its lock uses it to leave the file untouched.
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
    writeSync(fd, JSON.stringify(value, null, 1));
    fsyncSync(fd);
    closeSync(fd);
    guard?.();
  } catch (e) {
    try { closeSync(fd); } catch { /* closed already */ }
    try { unlinkSync(tmp); } catch { /* gone already */ }
    throw e;
  }
  renameSync(tmp, path);
}

const LOCK_STALE_MS = 15_000; // a holder that has not refreshed its lock for this long is taken for dead
const LOCK_HEARTBEAT_MS = 2_000;
const LOCK_WAIT_MS = 60_000; // longer than the staleness threshold, so a waiter outlasts a dead holder

/** The time as the file system that holds `dir` stamps it: a lock's age is judged by the clock that wrote its mtime. */
function fileSystemNow(dir: string): number {
  const probe = join(dir, `.now.${process.pid}.${randomBytes(6).toString('hex')}`);
  const fd = openSync(probe, 'wx', 0o600);
  closeSync(fd);
  try {
    return statSync(probe).mtimeMs;
  } finally {
    try { unlinkSync(probe); } catch { /* gone already */ }
  }
}
function readLock(lock: string): { content: string; mtimeMs: number } | undefined {
  try {
    return { content: readFileSync(lock, 'utf8'), mtimeMs: statSync(lock).mtimeMs };
  } catch {
    return undefined; // released in between
  }
}
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}
/** A lock is stale when its holder's process is gone, or when nobody has refreshed it for LOCK_STALE_MS. */
function isStale(seen: { content: string; mtimeMs: number }, dir: string): boolean {
  const pid = Number.parseInt(seen.content, 10);
  if (Number.isInteger(pid) && pid > 0 && !processAlive(pid)) return true;
  return fileSystemNow(dir) - seen.mtimeMs > LOCK_STALE_MS;
}
/**
 * Removes a stale lock as a compare-and-swap: only one process at a time may break locks (a second exclusive file),
 * and it removes the lock only if it still is the one that was judged stale. Without this, two waiters that both
 * saw the stale lock could each remove it, the second one removing the lock the first had just taken.
 */
function breakStaleLock(lock: string, staleContent: string, dir: string): void {
  const breaker = `${lock}.takeover`;
  try {
    closeSync(openSync(breaker, 'wx', 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    try {
      if (fileSystemNow(dir) - statSync(breaker).mtimeMs > LOCK_STALE_MS) unlinkSync(breaker); // its owner died mid-takeover
    } catch { /* released in between */ }
    return;
  }
  try {
    const current = readLock(lock);
    if (current && current.content === staleContent && isStale(current, dir)) unlinkSync(lock);
  } finally {
    try { unlinkSync(breaker); } catch { /* gone already */ }
  }
}

/**
 * Runs `fn` while holding an exclusive lock on `path`, across processes. Atomic replacement alone does not protect a
 * read-modify-write: two processes that read the same old content each write back their own version and one is lost.
 *
 * The lock is a file created with O_EXCL that names its holder (process id and a random token) and that the holder
 * refreshes while it works. `fn` receives a guard to call right before it commits: it throws if the lock is no
 * longer this holder's (it was suspended long enough to be taken for dead), so a holder that lost its lock neither
 * writes nor, on the way out, removes the lock of whoever holds it now.
 */
export async function withFileLock<T>(path: string, fn: (guard: () => void) => T | Promise<T>): Promise<T> {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = `${path}.lock`;
  const token = `${process.pid}:${randomBytes(12).toString('hex')}`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lock, 'wx', 0o600);
      writeSync(fd, token);
      closeSync(fd);
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    const seen = readLock(lock);
    if (seen && isStale(seen, dir)) breakStaleLock(lock, seen.content, dir);
    else if (Date.now() > deadline) throw new Error(`could not lock ${path}: another process holds ${lock}`);
    else await new Promise((r) => setTimeout(r, 5 + Math.floor(Math.random() * 25)));
  }
  const holds = (): boolean => readLock(lock)?.content === token;
  const skew = fileSystemNow(dir) - Date.now(); // refresh the mtime in the file system's own time
  const beat = setInterval(() => {
    try {
      if (holds()) { const t = new Date(Date.now() + skew); utimesSync(lock, t, t); }
    } catch { /* released or taken over */ }
  }, LOCK_HEARTBEAT_MS);
  beat.unref();
  try {
    return await fn(() => {
      if (!holds()) throw new Error(`lost the lock on ${path}: another process took it over; nothing was written`);
    });
  } finally {
    clearInterval(beat);
    if (holds()) {
      try { unlinkSync(lock); } catch { /* gone already */ }
    }
  }
}
