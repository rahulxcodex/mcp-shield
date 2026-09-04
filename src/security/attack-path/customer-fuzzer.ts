export interface CustomerToolDefinition {
  name: string;
  capabilities: string[];
  resources?: string[];
  destinations?: string[];
}

export interface CustomerEnvironment {
  tools: CustomerToolDefinition[];
  sensitiveAssets: string[];
  externalDestinations: string[];
  policies?: {
    denyEgress?: boolean;
    requireApprovalForSecrets?: boolean;
  };
}

export interface AttackPathFinding {
  riskScore: number;
  asset: string;
  path: string[];
  why: string;
  strategy: 'bounded-dfs' | 'bfs' | 'shortest-path' | 'capability-constrained';
}

export interface CustomerFuzzerReport {
  analyzedToolCount: number;
  discoveredPathsCount: number;
  maxRiskScore: number;
  highRiskFindings: AttackPathFinding[];
  summary: string;
}

export class CustomerEnvironmentAttackPathFuzzer {
  /**
   * Bounded Depth-First Search for dangerous paths from sensitive assets to external destinations
   */
  public static fuzzEnvironment(
    env: CustomerEnvironment,
    maxDepth: number = 4
  ): CustomerFuzzerReport {
    const findings: AttackPathFinding[] = [];

    // Map tools by capability
    const readTools = env.tools.filter(t =>
      t.capabilities.some(c => ['read', 'filesystem', 'database', 'secretAccess'].includes(c))
    );
    const transformTools = env.tools.filter(t =>
      t.capabilities.some(c => ['transform', 'compression', 'encoding', 'export'].includes(c))
    );
    const egressTools = env.tools.filter(t =>
      t.capabilities.some(c => ['network', 'egress', 'shell', 'exec'].includes(c))
    );

    // Strategy 1: Bounded DFS
    for (const asset of env.sensitiveAssets) {
      for (const rTool of readTools) {
        // Direct read -> egress
        for (const eTool of egressTools) {
          if (rTool.name !== eTool.name) {
            findings.push({
              riskScore: 90,
              asset,
              path: [`${rTool.name}.read`, `${eTool.name}.network`],
              why: `Direct exfiltration path: Read asset '${asset}' followed immediately by network egress`,
              strategy: 'bounded-dfs'
            });
          }
        }

        // Read -> Transform -> Egress
        if (maxDepth >= 3) {
          for (const tTool of transformTools) {
            for (const eTool of egressTools) {
              findings.push({
                riskScore: 94,
                asset,
                path: [`${rTool.name}.read`, `${tTool.name}.transform`, `${eTool.name}.network`],
                why: `Multi-stage exfiltration: sensitive source '${asset}' + transformation/staging + external destination`,
                strategy: 'capability-constrained'
              });
            }
          }
        }
      }
    }

    // Strategy 2: Shortest-Path Search to High-Value Assets
    for (const asset of env.sensitiveAssets) {
      const shortestRead = readTools[0];
      const shortestEgress = egressTools[0];
      if (shortestRead && shortestEgress) {
        findings.push({
          riskScore: 92,
          asset,
          path: [`${shortestRead.name}.read`, `${shortestEgress.name}.network`],
          why: `Shortest exfiltration vector to high-value asset '${asset}'`,
          strategy: 'shortest-path'
        });
      }
    }

    // Deduplicate findings by path string
    const seen = new Set<string>();
    const uniqueFindings = findings.filter(f => {
      const key = f.path.join(' -> ');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const maxRisk = uniqueFindings.reduce((m, f) => Math.max(m, f.riskScore), 0);

    return {
      analyzedToolCount: env.tools.length,
      discoveredPathsCount: uniqueFindings.length,
      maxRiskScore: maxRisk,
      highRiskFindings: uniqueFindings.sort((a, b) => b.riskScore - a.riskScore),
      summary: `Discovered ${uniqueFindings.length} dangerous attack paths (Max Risk: ${maxRisk}/100)`
    };
  }

  /**
   * Formats finding into standard roadmap compliance string
   */
  public static formatFinding(finding: AttackPathFinding): string {
    return [
      `Risk: ${finding.riskScore}/100`,
      '',
      'Asset:',
      `  ${finding.asset}`,
      '',
      'Path:',
      `  ${finding.path.join('\n  → ')}`,
      '',
      'Why:',
      `  ${finding.why}`
    ].join('\n');
  }
}
