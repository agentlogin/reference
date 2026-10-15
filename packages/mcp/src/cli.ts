import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { readPrivateConfig } from './config.js';
import { readCatalog, catalogView } from './catalog.js';
import { LoginRuntime } from './runtime.js';
import { createServer } from './server.js';
import { acquireStateLease } from './private-state.js';

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.includes('--help')) {
    process.stdout.write('Usage: agentlogin-mcp [--config /absolute/config.json]\n       agentlogin-mcp --check-config /absolute/config.json\n       agentlogin-mcp --check-catalog /absolute/catalog.json\n\nThe local stdio helper uses AGENTLOGIN_MCP_CONFIG when --config is absent.\nIt never reads credentials from tool arguments.\n');
    return;
  }
  try {
    if (args[0] === '--check-catalog' && args.length === 2) { const catalog = readCatalog(args[1]!); process.stdout.write(JSON.stringify({ valid: true, kind: catalog.kind, entries: catalogView([catalog]).length }) + '\n'); return; }
    const checking = args[0] === '--check-config';
    if (args.length && !((args[0] === '--config' || checking) && args.length === 2)) throw new Error('Invalid arguments; use --help');
    const file = args[1] ?? process.env.AGENTLOGIN_MCP_CONFIG;
    if (!file) throw new Error('Set AGENTLOGIN_MCP_CONFIG to an operator-owned config file; see --help');
    const config = readPrivateConfig(file);
    const runtime = new LoginRuntime(config);
    if (checking) { process.stdout.write('Configuration valid. No network requests made.\n'); return; }
    const release = acquireStateLease(config.stateDirectory);
    const handle = serveStdio(() => {
      const server = createServer(runtime);
      // Closing the local host ends pending work too. Release only as this process exits;
      // another helper must never overlap a still-running background sign-in.
      server.server.onclose = () => { release(); process.exit(0); };
      return server;
    });
    process.once('exit', release);
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => { void handle.close().finally(() => { release(); process.exit(0); }); });
  } catch {
    // Config validation may include a mistakenly pasted secret. Never print exception values.
    process.stderr.write('agentlogin-mcp: configuration or startup failed. Check the private config, catalog schemas, and state-directory lock; use --help.\n');
    process.exitCode = 1;
  }
}
