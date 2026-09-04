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
import { LicenseCommand } from './cli/commands/license';
import { LicenseManager } from './security/license-manager';
import { BenchmarkCommand } from './cli/commands/benchmark';
import { AttackCorpusCommand } from './cli/commands/attack-corpus';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

export * from './core/proxy';
export * from './core/mcp-protocol-state-machine';
export { ProtocolValidator, ProtocolValidatorConfig } from './core/protocol-validator';
export * from './core/ai-runtime-security';
export * from './core/broker/execution-broker';
export * from './core/guards/ingress-guard';
export * from './core/guards/tool-guard';
export * from './core/guards/output-guard';
export * from './core/lifecycle/lifecycle-manager';
export * from './security/policy-engine';
export * from './security/capability-manifest';
export * from './security/unicode-normalizer';
export * from './security/multi-interpreter-analyzer';
export * from './security/sanitizer';
export * from './security/rate-limiter';
export * from './security/canary';
export * from './security/jit-elevation';
export * from './security/attack-corpus';
export * from './security/intelligence-engine';
export * from './security/server-identity';
export * from './cloud/telemetry';
export * from './dashboard/server';

const args = process.argv.slice(2);
const command = args[0];

const bypassCommands = ['demo', 'install', 'license', 'enterprise', 'link', 'wrap', 'protect', 'scan', 'fix', 'dashboard', 'stats', 'report', 'replay', 'benchmark', 'attack-corpus'];
if (command && !bypassCommands.includes(command) && process.env.NODE_ENV !== 'test') {
  const licenseFile = path.join(os.homedir(), '.mcp-shield', 'license.key');
  if (fs.existsSync(licenseFile)) {
    const licenseManager = new LicenseManager();
    licenseManager.verifyLicense(fs.readFileSync(licenseFile, 'utf8').trim());
  }
}

if (command === 'demo') {
  DemoCommand.run(args.slice(1));
} else if (command === 'license') {
  LicenseCommand.run(args[1]);
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
} else if (command === 'wrap') {
  const dashDashIdx = args.indexOf('--');
  if (dashDashIdx === -1 || !args[dashDashIdx + 1]) {
    console.error('Usage: mcp-shield wrap [--key <api-key>] [--url <cloud-url>] -- <downstream-command> [args...]');
    process.exit(1);
  }

  // Parse any pre-dash flags
  for (let i = 1; i < dashDashIdx; i++) {
    if (args[i] === '--key' && args[i + 1]) {
      process.env.MCP_SHIELD_API_KEY = args[i + 1].trim();
      i++;
    } else if (args[i] === '--url' && args[i + 1]) {
      process.env.MCP_SHIELD_CLOUD_URL = args[i + 1].trim();
      i++;
    }
  }

  const targetCmd = args[dashDashIdx + 1];
  const targetArgs = args.slice(dashDashIdx + 2);
  
  // Start the proxy with the downstream MCP server
  const proxy = new ProxyServer(targetCmd, targetArgs, { enableDashboard: true });
  proxy.start().then(code => process.exit(code)).catch(err => {
    console.error('Fatal proxy error:', err);
    process.exit(1);
  });
} else if (command === 'benchmark') {
  BenchmarkCommand.run(args.slice(1)).catch(err => {
    console.error('Benchmark execution error:', err);
    process.exit(1);
  });
} else if (command === 'attack-corpus') {
  AttackCorpusCommand.run(args.slice(1)).then(() => process.exit(0)).catch(err => {
    console.error('Attack corpus error:', err);
    process.exit(1);
  });
} else if (command === 'enterprise') {
  // Launch the Next.js Enterprise Control Plane
  require('./cli/commands/dashboard').dashboardCmd.parse(['node', 'mcp-shield', 'dashboard', ...args.slice(1)]);
} else if (process.env.npm_lifecycle_event || require.main === module) {
  console.log(`
🛡️  MCP-SHIELD
Usage:
  mcp-shield demo [--dashboard]   Run interactive attack simulation & security demo.
  mcp-shield install              Quickly install and configure MCP-Shield.
  mcp-shield license <key>        Activate your MCP Shield enterprise license.
  mcp-shield scan                 Scan your MCP servers for security vulnerabilities.
  mcp-shield fix                  Automatically generate and apply security policies.
  mcp-shield protect              Auto-discover and protect MCP clients.
  mcp-shield benchmark [--json]   Run official MCP Security Benchmark across 6 dimensions.
  mcp-shield attack-corpus [cmd]  Query or verify attacks in proprietary agent corpus.
  mcp-shield link --key <key>     Pair this agent instance with your Cloud Dashboard.
  mcp-shield dashboard            Launch local real-time security dashboard.
  mcp-shield enterprise           Launch the full Next.js Enterprise Control Plane on-premise.
  mcp-shield stats [log_file]     View shareable security activity & blocked attacks report.
  mcp-shield replay <log_file>    Replay and verify tamper-evident audit logs.
  mcp-shield wrap -- <cmd> [args] Wrap an MCP server with the security gateway.
  `);
  process.exit(1);
}
