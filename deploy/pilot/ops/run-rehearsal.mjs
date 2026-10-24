#!/usr/bin/env node
// This entry point deliberately has no database-URL option. It owns an isolated cluster.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { tmpdir, cpus, totalmem, platform, arch } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../../..', import.meta.url));
const args = process.argv.slice(2);
assert.ok(args.length === 2 && args[0] === '--output', 'Usage: node deploy/pilot/ops/run-rehearsal.mjs --output <new-directory>');
const output = resolve(args[1]);
await mkdir(output, { mode: 0o700 }); // Refuse to overwrite previous evidence.
const work = await mkdtemp(join(tmpdir(), 'agentlogin-ops-'));
const data = join(work, 'data');
const bin = (name) => process.env.PG_BIN ? join(process.env.PG_BIN, name) : name;
let started = false;
let stopped = false;
let activeChild;
const report = {
  kind: 'disposable-postgresql-operational-rehearsal',
  startedAt: new Date().toISOString(),
  source: (await run('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim(),
  sourceDirty: (await run('git', ['status', '--porcelain'], { cwd: root })).stdout.trim() !== '',
  node: process.version,
  host: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model, logicalCpus: cpus().length, memoryBytes: totalmem() },
  postgres: (await run(bin('pg_ctl'), ['--version'])).stdout.trim(),
  passed: false,
  limitations: ['Loopback PostgreSQL is not production capacity or live replica routing evidence.', 'No production data, credentials, infrastructure, or external alert delivery is exercised.'],
};
report.toolingSha256 = Object.fromEntries(await Promise.all(['run-rehearsal.mjs', 'drills.test.ts', 'monitor.mjs', 'monitor.test.mjs'].map(async (name) => [name, createHash('sha256').update(await readFile(new URL(name, import.meta.url))).digest('hex')])));
const abort = () => { activeChild?.kill('SIGTERM'); };
process.once('SIGINT', abort);
process.once('SIGTERM', abort);
try {
  await run(bin('initdb'), ['-D', data, '-A', 'trust', '-U', 'postgres', '--no-locale', '--encoding=UTF8'], { timeout: 30_000 });
  const listener = createServer();
  await new Promise((yes, no) => { listener.once('error', no); listener.listen(0, '127.0.0.1', yes); });
  const port = listener.address().port;
  await new Promise((yes) => listener.close(yes));
  await run(bin('pg_ctl'), ['-D', data, '-l', join(work, 'postgres.log'), '-o', `-h 127.0.0.1 -p ${port} -k ${work} -c max_connections=80`, '-w', 'start'], { timeout: 30_000 });
  started = true;
  await run(bin('createdb'), ['-h', '127.0.0.1', '-p', String(port), '-U', 'postgres', '-T', 'template0', 'agentlogin_ops']);
  const env = { ...process.env, AGENTLOGIN_TEST_POSTGRES_URL: `postgresql://postgres@127.0.0.1:${port}/agentlogin_ops`, REQUIRE_POSTGRES_TESTS: '1', AGENTLOGIN_OPS_DISPOSABLE: '1', AGENTLOGIN_OPS_OUTPUT: output, AGENTLOGIN_OPS_WORK: work };
  // Real independent connections/processes and failure injection already maintained with their owning code.
  const tests = [
    'packages/store-postgres/test/store-contract.test.ts',
    'packages/store-postgres/test/concurrency.test.ts',
    'packages/store-postgres/test/runtime-disconnect.test.ts',
    'packages/store-postgres/test/recovery.test.ts',
    'packages/rp-store-postgres/test/handlers.test.ts',
    'examples/rp-hono/test/multi-host.test.ts',
    'examples/rp-hono/test/postgres-session.test.ts',
    'examples/rp-hono/test/session-runtime.test.ts',
    'examples/rp-hono/test/deployment.test.ts',
    'deploy/pilot/ops/monitor.test.mjs',
    'deploy/pilot/ops/drills.test.ts',
  ];
  report.suites = tests;
  const { createWriteStream } = await import('node:fs');
  const transcript = createWriteStream(join(output, 'tests.tap'), { mode: 0o600, flags: 'wx' });
  activeChild = spawn(process.execPath, ['--import', 'tsx', '--test', '--test-concurrency=1', '--test-reporter=tap', ...tests], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  activeChild.stdout.pipe(transcript, { end: false });
  activeChild.stderr.pipe(transcript, { end: false });
  const timer = setTimeout(() => activeChild.kill('SIGTERM'), 12 * 60_000);
  const result = await new Promise((yes, no) => { activeChild.once('error', no); activeChild.once('close', (code, signal) => yes({ code, signal })); });
  clearTimeout(timer);
  await new Promise((yes) => transcript.end(yes));
  report.testResult = result;
  const tap = await readFile(join(output, 'tests.tap'), 'utf8');
  report.counts = Object.fromEntries(['tests', 'pass', 'fail', 'skipped'].map((key) => [key, Number(tap.match(new RegExp(`^# ${key} (\\d+)$`, 'm'))?.[1] ?? -1)]));
  assert.equal(result.code, 0, 'Rehearsal failed; inspect tests.tap');
  assert.equal(report.counts.skipped, 0, 'Operational evidence cannot silently skip PostgreSQL tests');
  report.passed = true;
} catch (error) {
  // Never dump raw PostgreSQL error objects or connection strings into evidence.
  report.failure = error?.code ?? error?.name ?? 'Error';
  process.exitCode = 1;
} finally {
  if (started) {
    try { await run(bin('pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { timeout: 30_000 }); stopped = true; }
    catch { report.cleanupFailed = true; report.passed = false; process.exitCode = 1; }
  }
  if (!started || stopped) await rm(work, { recursive: true, force: true });
  report.clusterStopped = stopped;
  report.finishedAt = new Date().toISOString();
  await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ passed: report.passed, clusterStopped: stopped, report: join(output, 'report.json') }));
}
