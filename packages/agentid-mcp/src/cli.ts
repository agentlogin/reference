import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { readConfig } from './config.js';
import { AgentIdRuntime } from './runtime.js';
import { createServer } from './server.js';

export async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Usage: agentid-signin-mcp [--config /absolute/config.json]\n       agentid-signin-mcp --check-config /absolute/config.json\n\nAGENTID_MCP_CONFIG supplies the path when --config is omitted.\nThe config names a protected environment variable containing the AgentMail API key.\n');
    return;
  }
  try {
    if (args.length && !(args.length === 2 && ['--config', '--check-config'].includes(args[0]!))) throw new Error('Invalid arguments');
    const file = args[1] ?? process.env.AGENTID_MCP_CONFIG;
    if (!file) throw new Error('Configuration required');
    const config = readConfig(file);
    if (args[0] === '--check-config') { process.stdout.write('Configuration valid. No network requests made.\n'); return; }
    const runtime = new AgentIdRuntime(config);
    const handle = serveStdio(() => createServer(runtime));
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void handle.close().finally(() => process.exit(0)); });
  } catch {
    process.stderr.write('agentid-signin-mcp: configuration or startup failed. Check the private configuration; use --help.\n');
    process.exitCode = 1;
  }
}
