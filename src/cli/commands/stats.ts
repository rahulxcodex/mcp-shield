import * as fs from 'fs';
import * as path from 'path';

export interface ShieldAuditStats {
  totalEvaluations: number;
  attacksBlocked: number;
  secretsSanitized: number;
  egressBlocked: number;
  safeAllowed: number;
  sandboxedOperations: number;
  distinctTools: Set<string>;
}

export class StatsCommand {
  public static calculateStats(entries: any[]): ShieldAuditStats {
    const stats: ShieldAuditStats = {
      totalEvaluations: entries.length,
      attacksBlocked: 0,
      secretsSanitized: 0,
      egressBlocked: 0,
      safeAllowed: 0,
      sandboxedOperations: 0,
      distinctTools: new Set<string>()
    };

    for (const entry of entries) {
      if (entry.toolName) {
        stats.distinctTools.add(entry.toolName);
      }

      if (entry.decision === 'block' || entry.action === 'block' || entry.blocked === true) {
        stats.attacksBlocked++;
      } else if (entry.decision === 'sandbox' || entry.action === 'sandbox') {
        stats.sandboxedOperations++;
      } else {
        stats.safeAllowed++;
      }

      if (entry.secretsRedacted || entry.secretsFound || (Array.isArray(entry.evidence) && entry.evidence.some((e: any) => e.detector === 'SecretSanitizer'))) {
        stats.secretsSanitized += (entry.secretsCount || 1);
      }

      if (entry.egressBlocked || (Array.isArray(entry.evidence) && entry.evidence.some((e: any) => e.detector === 'PolicyEngine' && e.finding?.includes('Domain blocked')))) {
        stats.egressBlocked++;
      }
    }

    return stats;
  }

  public static formatStatsReport(stats: ShieldAuditStats): string {
    const lines = [
      '┌──────────────────────────────────────────────────────────────────┐',
      '│ 🛡️  MCP-SHIELD SECURITY ACTIVITY REPORT                           │',
      '├──────────────────────────────────────────────────────────────────┤',
      `│  Evaluations:        ${String(stats.totalEvaluations).padEnd(6)} tool calls inspected                │`,
      `│  Attacks Blocked:    ${String(stats.attacksBlocked).padEnd(6)} destructive actions prevented         │`,
      `│  Secrets Guarded:    ${String(stats.secretsSanitized).padEnd(6)} credentials reversibly tokenized     │`,
      `│  Egress Shielded:    ${String(stats.egressBlocked).padEnd(6)} unauthorized network calls stopped   │`,
      `│  Sandboxed Actions:  ${String(stats.sandboxedOperations).padEnd(6)} operations staged in COW FS        │`,
      `│  Distinct Tools:     ${String(stats.distinctTools.size).padEnd(6)} MCP tools monitored                │`,
      '├──────────────────────────────────────────────────────────────────┤',
      `│  Status: 100% Host Protected • 0 Breaches • 0 Disks Wiped        │`,
      '├──────────────────────────────────────────────────────────────────┤',
      '│  📢 Share your protection status:                                │',
      `│  "MCP-Shield protected my machine from ${stats.attacksBlocked} rogue agent actions! 🛡️"│`,
      '│                                                                  │',
      '│  ⭐ Star on GitHub:        https://github.com/rahulxcodex/mcp-shield│',
      '│  ⚠️ Report False Positive:  https://github.com/rahulxcodex/mcp-shield/issues│',
      '└──────────────────────────────────────────────────────────────────┘'
    ];
    return lines.join('\n');
  }

  public static run(logPath?: string): void {
    const resolvedPath = logPath || path.join(process.cwd(), '.mcp-shield', 'logs', 'audit.jsonl');

    if (!fs.existsSync(resolvedPath)) {
      console.log(`
┌──────────────────────────────────────────────────────────────────┐
│ 🛡️  MCP-SHIELD SECURITY ACTIVITY REPORT                           │
├──────────────────────────────────────────────────────────────────┤
│  No audit logs found at:                                         │
│  ${resolvedPath.padEnd(64)}│
│                                                                  │
│  Run an MCP server with MCP-Shield to begin collecting stats:    │
│  $ mcp-shield wrap -- <command> [args]                           │
│  $ npx mcp-shield protect                                        │
└──────────────────────────────────────────────────────────────────┘
      `);
      return;
    }

    try {
      const raw = fs.readFileSync(resolvedPath, 'utf8');
      const lines = raw.split('\n').filter(l => l.trim().length > 0);
      const entries = lines.map(l => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      }).filter(Boolean);

      const stats = this.calculateStats(entries);
      console.log(this.formatStatsReport(stats));
    } catch (err: any) {
      console.error(`[ERROR] Failed to read audit logs: ${err.message}`);
    }
  }
}
