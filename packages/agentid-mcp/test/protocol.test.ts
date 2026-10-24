import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { readConfig } from '../src/config.js';

const bin = fileURLToPath(new URL('../bin/agentid-signin-mcp.js', import.meta.url));
const fixture = { version: 1, inbox: 'scout@agentmail.to', credentialEnv: 'AGENTMAIL_TEST_NOT_SET', applications: {} };
for (const mode of ['legacy', { pin: '2026-07-28' }] as const) {
  test(`real stdio client negotiates tools and rejects credential/raw-token arguments (${typeof mode === 'string' ? mode : mode.pin})`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentid-wire-')); const config = join(dir, 'config.json');
    writeFileSync(config, JSON.stringify(fixture), { mode: 0o600 });
    const transport = new StdioClientTransport({ command: process.execPath, args: [bin, '--config', config], stderr: 'pipe' });
    let stderr = ''; transport.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
    const client = new Client({ name: 'agentid-test', version: '1.0.0' }, { versionNegotiation: { mode } });
    try {
      await client.connect(transport);
      assert.equal(client.getServerVersion()?.version, JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
      const tools = (await client.listTools()).tools;
      assert.equal(tools.length, 6); assert.equal(tools.some((tool) => /authorize|send|revoke/.test(tool.name)), false);
      assert.equal(tools.find((tool) => tool.name === 'agentid_connect')?.annotations?.readOnlyHint, false);
      const inventory = await client.callTool({ name: 'agentid_inventory', arguments: {} });
      assert.match(JSON.stringify(inventory), /scout@agentmail.to/); assert.match(JSON.stringify(inventory), /browserCompletionRequired/);
      for (const args of [ { application: 'notes', attempt: 'bad', acceptDisclosure: false, credential: 'DO_NOT_ECHO' }, { auth_token: 'DO_NOT_ECHO' } ]) {
        const bad = await client.callTool({ name: 'agentid_connect', arguments: args });
        assert.equal(bad.isError, true); assert.doesNotMatch(JSON.stringify(bad), /DO_NOT_ECHO/);
      }
      const missing = await client.callTool({ name: 'agentid_list_apps', arguments: {} });
      assert.equal(missing.isError, true); assert.match(JSON.stringify(missing), /credential_missing/);
      assert.doesNotMatch(JSON.stringify(missing), /Bearer|stack|AGENTMAIL_TEST/);
    } finally { await client.close(); rmSync(dir, { recursive: true, force: true }); }
    assert.doesNotMatch(stderr, /DO_NOT_ECHO/);
  });
}

test('private config rejects symlinks and insecure mode; CLI failures never echo input', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentid-config-'));
  try {
    const path = join(dir, 'config.json'); writeFileSync(path, JSON.stringify(fixture), { mode: 0o600 });
    assert.equal(readConfig(path).inbox, fixture.inbox);
    const link = join(dir, 'link.json'); symlinkSync(path, link); assert.throws(() => readConfig(link));
    chmodSync(path, 0o644); assert.throws(() => readConfig(path)); chmodSync(path, 0o600);
    const ok = spawnSync(process.execPath, [bin, '--check-config', path], { encoding: 'utf8' }); assert.equal(ok.status, 0); assert.match(ok.stdout, /No network/);
    writeFileSync(path, JSON.stringify({ ...fixture, apiKey: 'DO_NOT_ECHO' }));
    const bad = spawnSync(process.execPath, [bin, '--check-config', path], { encoding: 'utf8' }); assert.equal(bad.status, 1); assert.equal(bad.stdout, ''); assert.doesNotMatch(bad.stderr, /DO_NOT_ECHO/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
