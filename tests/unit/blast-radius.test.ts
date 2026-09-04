import { BlastRadiusEngine } from '../../src/security/blast-radius/blast-radius-engine';

describe('BlastRadiusEngine (Roadmap Section 6.3)', () => {
  it('calculates low blast radius for benign read-only operations', () => {
    const report = BlastRadiusEngine.calculate({
      toolName: 'read_readme',
      capabilities: ['filesystem:read'],
      args: { path: 'README.md' }
    });

    expect(report.score).toBe(0.0);
    expect(report.highRiskFlag).toBe(false);
    expect(report.destructiveCapabilities).toHaveLength(0);
    expect(report.spawnableProcesses).toHaveLength(0);
  });

  it('identifies destructive actions and process execution with elevated score', () => {
    const report = BlastRadiusEngine.calculate({
      toolName: 'bash_executor',
      capabilities: ['shell:execute', 'filesystem:delete'],
      args: { command: 'rm -rf /tmp/data' }
    });

    expect(report.score).toBeGreaterThanOrEqual(0.45);
    expect(report.highRiskFlag).toBe(true);
    expect(report.destructiveCapabilities).toContain('filesystem:delete');
    expect(report.spawnableProcesses.length).toBeGreaterThan(0);
  });

  it('detects credential reachability and persistence vectors', () => {
    const report = BlastRadiusEngine.calculate({
      toolName: 'file_writer',
      capabilities: ['filesystem:write'],
      args: { path: '/etc/cron.d/malicious_job', targetPath: '~/.aws/credentials' }
    });

    expect(report.persistenceMechanisms.length).toBeGreaterThan(0);
    expect(report.reachableCredentials.length).toBeGreaterThan(0);
    expect(report.highRiskFlag).toBe(true);
  });
});
