import { CustomerEnvironmentAttackPathFuzzer, CustomerEnvironment } from '../../src/security/attack-path/customer-fuzzer';

describe('Roadmap Step 2 — Customer Environment Attack Path Fuzzer', () => {
  const customerEnv: CustomerEnvironment = {
    tools: [
      { name: 'pg_query', capabilities: ['database', 'read'], resources: ['postgres://prod-db'] },
      { name: 'data_transformer', capabilities: ['transform', 'export'] },
      { name: 'tar_compress', capabilities: ['compression'] },
      { name: 's3_uploader', capabilities: ['network', 'egress'], destinations: ['https://bucket.s3.amazonaws.com'] },
      { name: 'send_webhook', capabilities: ['network'], destinations: ['https://hooks.slack.com'] },
      { name: 'local_linter', capabilities: ['local'] }
    ],
    sensitiveAssets: ['credentials', 'customer_pii', 'api_tokens'],
    externalDestinations: ['https://attacker-webhook.com', 'https://bucket.s3.amazonaws.com']
  };

  it('identifies exfiltration paths using bounded DFS and capability constraints', () => {
    const report = CustomerEnvironmentAttackPathFuzzer.fuzzEnvironment(customerEnv, 3);
    expect(report.analyzedToolCount).toBe(6);
    expect(report.discoveredPathsCount).toBeGreaterThan(0);
    expect(report.maxRiskScore).toBeGreaterThanOrEqual(90);

    const topFinding = report.highRiskFindings[0];
    expect(topFinding.riskScore).toBeGreaterThanOrEqual(90);
    expect(topFinding.path.length).toBeGreaterThanOrEqual(2);
    expect(topFinding.path[0]).toContain('pg_query');

    // Check report formatting matches roadmap output format
    const formatted = CustomerEnvironmentAttackPathFuzzer.formatFinding(topFinding);
    expect(formatted).toContain('Risk:');
    expect(formatted).toContain('Asset:');
    expect(formatted).toContain('Path:');
    expect(formatted).toContain('Why:');
  });

  it('produces empty findings if environment contains zero egress or read tools', () => {
    const isolatedEnv: CustomerEnvironment = {
      tools: [
        { name: 'calculator', capabilities: ['compute'] },
        { name: 'formatter', capabilities: ['format'] }
      ],
      sensitiveAssets: ['credentials'],
      externalDestinations: []
    };

    const report = CustomerEnvironmentAttackPathFuzzer.fuzzEnvironment(isolatedEnv);
    expect(report.discoveredPathsCount).toBe(0);
    expect(report.maxRiskScore).toBe(0);
  });
});
