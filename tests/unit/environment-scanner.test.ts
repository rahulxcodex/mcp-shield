import { EnvironmentAttackScanner, DiscoveredTool } from '../../src/security/graph/environment-scanner';

describe('Environment-Specific Attack Discovery Scanner (Roadmap Section 17)', () => {
  it('identifies exfiltration paths and generates synthetic remediation', () => {
    const environmentTools: DiscoveredTool[] = [
      {
        name: 'secret_manager',
        capabilities: {
          filesystemRead: true,
          filesystemWrite: false,
          shellExecution: false,
          networkAccess: false,
          processSpawn: false,
          destructiveOperation: false,
          secretAccess: true
        }
      },
      {
        name: 'data_transformer',
        capabilities: {
          filesystemRead: true,
          filesystemWrite: true,
          shellExecution: false,
          networkAccess: false,
          processSpawn: false,
          destructiveOperation: false,
          secretAccess: false
        }
      },
      {
        name: 'curl_uploader',
        capabilities: {
          filesystemRead: false,
          filesystemWrite: false,
          shellExecution: false,
          networkAccess: true,
          processSpawn: false,
          destructiveOperation: false,
          secretAccess: false
        }
      }
    ];

    const report = EnvironmentAttackScanner.scanEnvironment(environmentTools);

    expect(report.scannedToolCount).toBe(3);
    expect(report.criticalPathsFound).toBeGreaterThan(0);
    expect(report.highestRiskScore).toBeGreaterThanOrEqual(75);
    expect(report.attackPaths[0].remediation).toBeDefined();
    expect(report.attackPaths[0].syntheticPayload).toHaveProperty('attackVector', 'COMPOSED_CAPABILITY_EXFILTRATION');
  });

  it('reports zero critical paths for completely isolated environment', () => {
    const isolatedTools: DiscoveredTool[] = [
      {
        name: 'isolated_calculator',
        capabilities: {
          filesystemRead: false,
          filesystemWrite: false,
          shellExecution: false,
          networkAccess: false,
          processSpawn: false,
          destructiveOperation: false,
          secretAccess: false
        }
      }
    ];

    const report = EnvironmentAttackScanner.scanEnvironment(isolatedTools);
    expect(report.criticalPathsFound).toBe(0);
    expect(report.highestRiskScore).toBe(0);
  });
});
