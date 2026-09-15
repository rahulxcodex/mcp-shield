import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { ProxyServer } from './core/proxy';
import { ProtectCommand } from './cli/commands/protect';
import { ReplayCommand } from './cli/commands/replay';
import { ReplayEvalCommand } from './cli/commands/replay-eval';
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
import { AuditCommand } from './cli/commands/audit';
import { ConfigLoader } from './security/config';
import { OfflineAirGapEnforcer } from './security/airgap/offline-enforcer';
import { HumanOversightService } from './security/oversight/human-oversight-service';

export async function runCli(args: string[] = process.argv.slice(2)): Promise<void> {
  const invokedBin = path.basename(process.argv[1] || '');
  if (invokedBin.includes('audit') && args[0] !== 'audit') {
    args.unshift('audit');
  }
  const command = args[0];

  if (args.includes('--offline')) {
    OfflineAirGapEnforcer.activate();
  }

  const bypassCommands = ['demo', 'install', 'license', 'enterprise', 'link', 'wrap', 'protect', 'scan', 'fix', 'dashboard', 'stats', 'report', 'replay', 'replay-eval', 'benchmark', 'attack-corpus', 'audit', 'config', 'oversight'];
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
  } else if (command === 'replay-eval') {
    await ReplayEvalCommand.run(args[1]);
    process.exit(0);
  } else if (command === 'stats' || command === 'report') {
    StatsCommand.run(args[1]);
    process.exit(0);
  } else if (command === 'install') {
    InstallCommand.run();
  } else if (command === 'scan') {
    let format: string | undefined;
    let failOn: 'critical' | 'high' | 'medium' | undefined;
    let json = false;
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--json') json = true;
      else if (args[i].startsWith('--format=')) format = args[i].split('=')[1];
      else if (args[i] === '--format' && args[i + 1]) { format = args[i + 1]; i++; }
      else if (args[i].startsWith('--fail-on=')) failOn = args[i].split('=')[1] as any;
      else if (args[i] === '--fail-on' && args[i + 1]) { failOn = args[i + 1] as any; i++; }
    }
    ScanCommand.run({ json, format, failOn });
  } else if (command === 'audit') {
    AuditCommand.run(args.slice(1));
    process.exit(0);
  } else if (command === 'config') {
    if (args[1] === 'check' || args[1] === 'validate') {
      try {
        const config = ConfigLoader.load(args[2]);
        console.log(`\x1b[32m✓ Configuration '${args[2] || 'shield.config.yaml'}' is valid (mode: ${config.mode || 'enforce'}).\x1b[0m`);
        process.exit(0);
      } catch (err: any) {
        console.error(`\x1b[31m✗ Configuration error: ${err.message}\x1b[0m`);
        process.exit(1);
      }
    } else {
      console.log('Usage: mcp-shield config check [config-file]');
      process.exit(0);
    }
  } else if (command === 'oversight') {
    const sub = args[1];
    const oversight = new HumanOversightService();
    if (sub === 'list') {
      const list = oversight.listPending();
      console.log(JSON.stringify({ pending: list, count: list.length }, null, 2));
      process.exit(0);
    } else if (sub === 'approve' && args[2]) {
      const res = oversight.approve(args[2], args[3] || 'cli-admin');
      console.log(JSON.stringify(res, null, 2));
      process.exit(0);
    } else if (sub === 'reject' && args[2]) {
      const res = oversight.reject(args[2], args[3] || 'cli-admin');
      console.log(JSON.stringify(res, null, 2));
      process.exit(0);
    } else {
      console.log('Usage: mcp-shield oversight [list | approve <id> [reviewer] | reject <id> [reviewer]]');
      process.exit(0);
    }
  } else if (command === 'fix') {
    FixCommand.run();
  } else if (command === 'link') {
    await LinkCommand.run(args.slice(1));
    process.exit(0);
  } else if (command === 'dashboard') {
    const server = new DashboardServer(3333);
    try {
      await server.start();
      console.log('🛡️  MCP-Shield Dashboard active at: ' + server.getUrl());
    } catch (err) {
      console.error('Failed to start dashboard:', err);
      process.exit(1);
    }
  } else if (command === 'wrap') {
    const dashDashIdx = args.indexOf('--');
    if (dashDashIdx === -1 || !args[dashDashIdx + 1]) {
      console.error('Usage: mcp-shield wrap [--shadow] [--key <api-key>] [--url <cloud-url>] -- <downstream-command> [args...]');
      process.exit(1);
    }

    let shadowMode = false;
    // Parse any pre-dash flags
    for (let i = 1; i < dashDashIdx; i++) {
      if (args[i] === '--key' && args[i + 1]) {
        process.env.MCP_SHIELD_API_KEY = args[i + 1].trim();
        i++;
      } else if (args[i] === '--url' && args[i + 1]) {
        process.env.MCP_SHIELD_CLOUD_URL = args[i + 1].trim();
        i++;
      } else if (args[i] === '--shadow' || args[i] === '--dry-run') {
        shadowMode = true;
      }
    }

    const targetCmd = args[dashDashIdx + 1];
    const targetArgs = args.slice(dashDashIdx + 2);

    // Start the proxy with the downstream MCP server
    const proxy = new ProxyServer(targetCmd, targetArgs, { enableDashboard: true, shadowMode });
    try {
      const code = await proxy.start();
      process.exit(code);
    } catch (err) {
      console.error('Fatal proxy error:', err);
      process.exit(1);
    }
  } else if (command === 'benchmark') {
    try {
      await BenchmarkCommand.run(args.slice(1));
    } catch (err) {
      console.error('Benchmark execution error:', err);
      process.exit(1);
    }
  } else if (command === 'attack-corpus') {
    try {
      await AttackCorpusCommand.run(args.slice(1));
      process.exit(0);
    } catch (err) {
      console.error('Attack corpus error:', err);
      process.exit(1);
    }
  } else if (command === 'enterprise') {
    require('./cli/commands/dashboard').dashboardCmd.parse(['node', 'mcp-shield', 'dashboard', ...args.slice(1)]);
  } else {
    console.log([
      '🛡️  MCP-SHIELD',
      'Usage:',
      '  mcp-shield demo [--dashboard]   Run interactive attack simulation & security demo.',
      '  mcp-shield install              Quickly install and configure MCP-Shield.',
      '  mcp-shield license <key>        Activate your MCP Shield enterprise license.',
      '  mcp-shield scan [--format=sarif] Scan your MCP servers for security vulnerabilities.',
      '  mcp-shield audit export/verify  Enterprise SIEM export (CEF/Syslog) & Merkle verification.',
      '  mcp-shield config check [file]  Validate MCP-Shield configuration syntax.',
      '  mcp-shield fix                  Automatically generate and apply security policies.',
      '  mcp-shield protect              Auto-discover and protect MCP clients.',
      '  mcp-shield benchmark [--json]   Run official MCP Security Benchmark across 6 dimensions.',
      '  mcp-shield attack-corpus [cmd]  Query or verify attacks in proprietary agent corpus.',
      '  mcp-shield link --key <key>     Pair this agent instance with your Cloud Dashboard.',
      '  mcp-shield dashboard            Launch local real-time security dashboard.',
      '  mcp-shield enterprise           Launch the full Next.js Enterprise Control Plane on-premise.',
      '  mcp-shield stats [log_file]     View shareable security activity & blocked attacks report.',
      '  mcp-shield replay <log_file>    Replay and verify tamper-evident audit logs.',
      '  mcp-shield replay-eval <log>    Replay historical events & diff decisions against v2.0 engine.',
      '  mcp-shield wrap [--shadow] -- <cmd> [args] Wrap an MCP server with the security gateway.'
    ].join('\n'));
    process.exit(1);
  }
}

if (require.main === module) {
  runCli().catch(err => {
    console.error('CLI Fatal Error:', err);
    process.exit(1);
  });
}
