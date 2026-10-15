import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

for (const mode of ['legacy', { pin: '2026-07-28' }] as const) {
  test(`real stdio MCP client lists, calls and validates tools (${typeof mode === 'string' ? mode : mode.pin})`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentlogin-mcp-wire-'));
    const config = join(dir, 'config.json');
    writeFileSync(config, JSON.stringify({ version: 1, stateDirectory: join(dir, 'private'), identities: { scout: { handle: 'scout@example.com' } }, applications: {} }), { mode: 0o600 });
    const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../bin/agentlogin-mcp.js', import.meta.url)), '--config', config], stderr: 'pipe' });
    let stderr = ''; transport.stderr?.on('data', (v) => { stderr += v.toString(); });
    const client = new Client({ name: 'agentlogin-mcp-test', version: '1.0.0' }, { versionNegotiation: { mode } });
    try {
      await client.connect(transport);
      const tools = await client.listTools();
      assert.equal(tools.tools.length, 9);
      assert.equal(tools.tools.find((v) => v.name === 'agentlogin_request')?.annotations?.readOnlyHint, false);
      const result = await client.callTool({ name: 'agentlogin_inventory', arguments: {} });
      assert.equal(result.isError, undefined);
      assert.match(JSON.stringify(result), /scout@example.com/);
      assert.doesNotMatch(JSON.stringify(result), /keys.json|privateJwk|polling_token/);
      const invalid = await client.callTool({ name: 'agentlogin_sign_in', arguments: { identity: 'scout', application: 'notes', credential: 'DO_NOT_ACCEPT' } });
      assert.equal(invalid.isError, true);
      const missing = await client.callTool({ name: 'agentlogin_sign_in', arguments: { identity: 'scout', application: 'notes' } });
      assert.equal(missing.isError, true);
      assert.match(JSON.stringify(missing), /not_configured/);
    } finally { await client.close(); rmSync(dir, { recursive: true, force: true }); }
    assert.doesNotMatch(stderr, /DO_NOT_ACCEPT/);
  });
}
