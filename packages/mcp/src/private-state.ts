import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';

export function privateDirectory(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink() || (typeof process.getuid === 'function' && (st.uid !== process.getuid() || (st.mode & 0o077) !== 0))) throw new Error('State directory must be owned by you with mode 0700');
}
export function readState(file: string): unknown {
  if (!existsSync(file)) return undefined;
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 64 * 1024 || (typeof process.getuid === 'function' && (st.uid !== process.getuid() || (st.mode & 0o077) !== 0))) throw new Error('Invalid private state file');
    return JSON.parse(readFileSync(fd, 'utf8'));
  } finally { closeSync(fd); }
}
export function writeState(file: string, value: unknown) {
  privateDirectory(dirname(file));
  const temporary = `${file}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, 'wx', 0o600);
  try {
    try { writeFileSync(fd, JSON.stringify(value)); fsyncSync(fd); }
    finally { closeSync(fd); }
    renameSync(temporary, file);
  } catch (error) { try { unlinkSync(temporary); } catch {} throw error; }
}
/** One serving process per private directory. Never steal a lock from a suspended process. */
export function acquireStateLease(dir: string): () => void {
  privateDirectory(dir);
  const file = join(dir, 'mcp-server.lock');
  const marker = `${process.pid}:${randomUUID()}`;
  let fd: number;
  try { fd = openSync(file, 'wx', 0o600); }
  catch { throw new Error('State directory is already in use. Stop all helpers before removing an abandoned mcp-server.lock.'); }
  try { writeFileSync(fd, marker); }
  finally { closeSync(fd); }
  return () => {
    try { if (readFileSync(file, 'utf8') === marker) unlinkSync(file); } catch {}
  };
}
