import { ProxyServer } from './core/proxy';
import { ProtectCommand } from './cli/commands/protect';
import { ReplayCommand } from './cli/commands/replay';
import { InstallCommand } from './cli/commands/install';
import { ScanCommand } from './cli/commands/scan';
import { FixCommand } from './cli/commands/fix';
import { StatsCommand } from './cli/commands/stats';
import { LinkCommand } from './cli/commands/link';
import { DemoCommand } from './cli/commands/demo';
import { DashboardServer } from './dashboard/server';

export * from './core/proxy';
export * from './security/policy-engine';
export * from './security/sanitizer';
export * from './security/rate-limiter';
export * from './cloud/telemetry';
export * from './dashboard/server';

const args = process.argv.slice(2);
const command = args[0];

if (command === 'demo') {
  DemoCommand.run(args.slice(1));
} else if (command === 'protect') {
  ProtectCommand.run();
  process.exit(0);
} else if (command === 'replay') {
  ReplayCommand.run(args[1]);
  process.exit(0);
} else if (command === 'stats' || command === 'report') {
  StatsCommand.run(args[1]);
  process.exit(0);
} else if (command === 'install') {
  InstallCommand.run();
} else if (command === 'scan') {
  ScanCommand.run();
} else if (command === 'fix') {
  FixCommand.run();
} else if (command === 'link') {
  LinkCommand.run(args.slice(1)).then(() => process.exit(0)).catch(() => process.exit(1));
} else if (command === 'dashboard') {
  const server = new DashboardServer(3333);
  server.start().then(port => {
    console.log(`🛡️  MCP-Shield Dashboard active at: ${server.getUrl()}`);
  }).catch(err => {
    console.error('Failed to start dashboard:', err);
    process.exit(1);
  });
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
} else if (process.env.npm_lifecycle_event || require.main === module) {
  console.log(`
🛡️  MCP-SHIELD
Usage:
  mcp-shield demo [--dashboard]   Run interactive attack simulation & security demo.
  mcp-shield install              Quickly install and configure MCP-Shield.
  mcp-shield scan                 Scan your MCP servers for security vulnerabilities.
  mcp-shield fix                  Automatically generate and apply security policies.
  mcp-shield protect              Auto-discover and protect MCP clients.
  mcp-shield link --key <key>     Pair this agent instance with your Cloud Dashboard.
  mcp-shield dashboard            Launch local real-time security dashboard.
  mcp-shield stats [log_file]     View shareable security activity & blocked attacks report.
  mcp-shield replay <log_file>    Replay and verify tamper-evident audit logs.
  mcp-shield wrap -- <cmd> [args] Wrap an MCP server with the security gateway.
  `);
  process.exit(1);
}
