import { StatsCommand, ShieldAuditStats } from '../../src/cli/commands/stats';

describe('StatsCommand & Security Activity Reporting', () => {
  it('should accurately aggregate intercepted events and blocked attacks', () => {
    const mockEntries = [
      { toolName: 'bash', decision: 'block', evidence: [{ detector: 'ASTAnalyzer', finding: 'rm -rf /' }] },
      { toolName: 'bash', decision: 'block', evidence: [{ detector: 'ASTAnalyzer', finding: 'mkfs.ext4' }] },
      { toolName: 'filesystem', decision: 'sandbox', action: 'sandbox', secretsRedacted: true, secretsCount: 2 },
      { toolName: 'fetch', decision: 'block', egressBlocked: true, evidence: [{ detector: 'PolicyEngine', finding: 'Domain blocked' }] },
      { toolName: 'git', decision: 'allow' },
      { toolName: 'git', decision: 'allow' }
    ];

    const stats = StatsCommand.calculateStats(mockEntries);

    expect(stats.totalEvaluations).toBe(6);
    expect(stats.attacksBlocked).toBe(3);
    expect(stats.sandboxedOperations).toBe(1);
    expect(stats.safeAllowed).toBe(2);
    expect(stats.secretsSanitized).toBe(2);
    expect(stats.egressBlocked).toBe(1);
    expect(stats.distinctTools.size).toBe(4);
    expect(stats.distinctTools.has('bash')).toBe(true);
    expect(stats.distinctTools.has('filesystem')).toBe(true);
  });

  it('should format a clean, shareable ASCII report string', () => {
    const mockStats: ShieldAuditStats = {
      totalEvaluations: 42,
      attacksBlocked: 5,
      secretsSanitized: 12,
      egressBlocked: 2,
      safeAllowed: 35,
      sandboxedOperations: 2,
      distinctTools: new Set(['bash', 'filesystem', 'git'])
    };

    const report = StatsCommand.formatStatsReport(mockStats);

    expect(report).toContain('MCP-SHIELD SECURITY ACTIVITY REPORT');
    expect(report).toContain('42     tool calls inspected');
    expect(report).toContain('5      destructive actions prevented');
    expect(report).toContain('12     credentials reversibly tokenized');
    expect(report).toContain('MCP-Shield protected my machine from 5 rogue agent actions!');
    expect(report).toContain('github.com/rahulxcodex/mcp-shield');
  });

  it('should handle empty log entries gracefully', () => {
    const stats = StatsCommand.calculateStats([]);
    expect(stats.totalEvaluations).toBe(0);
    expect(stats.attacksBlocked).toBe(0);
    expect(stats.secretsSanitized).toBe(0);
    expect(stats.distinctTools.size).toBe(0);

    const report = StatsCommand.formatStatsReport(stats);
    expect(report).toContain('0      tool calls inspected');
  });
});
