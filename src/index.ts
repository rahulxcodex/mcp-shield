import { ProxyServer } from './core/proxy';
import { ProtectCommand } from './cli/commands/protect';
import { ReplayCommand } from './cli/commands/replay';
import { InstallCommand } from './cli/commands/install';
import { ScanCommand } from './cli/commands/scan';
import { FixCommand } from './cli/commands/fix';

const args = process.argv.slice(2);
const command = args[0];

if (command === 'protect') {
  ProtectCommand.run();
  process.exit(0);
} else if (command === 'replay') {
  ReplayCommand.run(args[1]);
  process.exit(0);
} else if (command === 'install') {
  InstallCommand.run();
} else if (command === 'scan') {
  ScanCommand.run();
} else if (command === 'fix') {
  FixCommand.run();
} else if (command === 'wrap' && args[1] === '--') {
  const targetCmd = args[2];
  const targetArgs = args.slice(3);
  
  if (!targetCmd) {
    console.error('Usage: mcp-shield wrap -- <command> [args]');
    process.exit(1);
  }
  
  // Start the proxy with the downstream MCP server
  const proxy = new ProxyServer(targetCmd, targetArgs, { enableDashboard: true });
  proxy.start().then(code => process.exit(code)).catch(err => {
    console.error('Fatal proxy error:', err);
    process.exit(1);
  });
} else {
  console.log(`
🛡️  MCP-SHIELD
Usage:
  mcp-shield install              Quickly install and configure MCP-Shield.
  mcp-shield scan                 Scan your MCP servers for security vulnerabilities.
  mcp-shield fix                  Automatically generate and apply security policies.
  mcp-shield protect              Auto-discover and protect MCP clients.
  mcp-shield replay <log_file>    Replay and verify tamper-evident audit logs.
  mcp-shield wrap -- <cmd> [args] Wrap an MCP server with the security gateway.
  `);
  process.exit(1);
}
