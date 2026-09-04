import { AttackPath, AttackNode, SecurityDecision } from './attack-path-types';

export interface ChainEvaluationResult {
  isDangerous: boolean;
  decision: SecurityDecision;
  why: string;
  contributingNodes: string[];
}

export class AttackPathEngine {
  private callHistory: Array<{
    toolName: string;
    capabilities: string[];
    args: Record<string, any>;
    timestamp: number;
  }> = [];

  /**
   * Evaluates an in-flight tool invocation against the accumulated sequence history
   */
  public evaluateStep(
    toolName: string,
    capabilities: string[],
    args: Record<string, any> = {}
  ): SecurityDecision {
    this.callHistory.push({
      toolName,
      capabilities,
      args,
      timestamp: Date.now()
    });

    const chainAnalysis = this.analyzeAccumulatedChain();
    if (chainAnalysis.isDangerous) {
      return chainAnalysis.decision;
    }

    return {
      action: 'ALLOW',
      riskScore: 0.1
    };
  }

  /**
   * Resets history for new session
   */
  public reset(): void {
    this.callHistory = [];
  }

  /**
   * Analyzes an explicit declarative AttackPath definition
   */
  public evaluateDeclarativePath(path: AttackPath): SecurityDecision {
    const nodeNames = path.nodes.map(n => n.toolName.toLowerCase());
    const capabilities = path.nodes.flatMap(n => n.capabilities.map(c => c.toLowerCase()));

    const hasSensitiveSource = capabilities.some(c =>
      c.includes('read') || c.includes('secret') || c.includes('database') || c.includes('filesystem')
    ) || nodeNames.some(n => n.includes('database') || n.includes('read') || n.includes('export') || n.includes('credential'));

    const hasTransformation = capabilities.some(c =>
      c.includes('transform') || c.includes('encode') || c.includes('compress')
    ) || nodeNames.some(n => n.includes('transform') || n.includes('compress') || n.includes('export') || n.includes('zip'));

    const hasEgressDestination = capabilities.some(c =>
      c.includes('network') || c.includes('upload') || c.includes('egress') || c.includes('http') || c.includes('exec')
    ) || nodeNames.some(n => n.includes('upload') || n.includes('post') || n.includes('send') || n.includes('curl') || n.includes('webhook'));

    if (hasSensitiveSource && hasEgressDestination) {
      const isExfiltrationChain = hasTransformation || path.objective === 'exfiltration';
      return {
        action: 'BLOCK',
        riskScore: isExfiltrationChain ? 0.95 : 0.85,
        dangerousChainIdentified: true,
        chainExplanation: `DANGEROUS MULTI-TOOL CHAIN: Objective [${path.objective}] detected across ${path.nodes.length} nodes (sensitive source + egress destination). Path: ${path.nodes.map(n => n.toolName).join(' -> ')}`
      };
    }

    return {
      action: 'ALLOW',
      riskScore: 0.1,
      dangerousChainIdentified: false
    };
  }

  /**
   * Detects multi-step attack chains in historical sequence
   */
  private analyzeAccumulatedChain(): ChainEvaluationResult {
    const recent = this.callHistory.slice(-10); // Look at last 10 calls
    if (recent.length < 2) {
      return {
        isDangerous: false,
        decision: { action: 'ALLOW', riskScore: 0.0 },
        why: 'Insufficient history depth',
        contributingNodes: []
      };
    }

    let hasSensitiveRead = false;
    let hasTransform = false;
    let hasEgress = false;
    const contributingNodes: string[] = [];

    for (const step of recent) {
      const name = step.toolName.toLowerCase();
      const caps = step.capabilities.map(c => c.toLowerCase());

      if (
        caps.includes('read') ||
        caps.includes('database') ||
        name.includes('read') ||
        name.includes('db') ||
        name.includes('fetch_secret')
      ) {
        hasSensitiveRead = true;
        contributingNodes.push(step.toolName);
      }

      if (
        caps.includes('transform') ||
        caps.includes('compress') ||
        name.includes('export') ||
        name.includes('transform') ||
        name.includes('zip')
      ) {
        hasTransform = true;
        contributingNodes.push(step.toolName);
      }

      if (
        caps.includes('network') ||
        caps.includes('upload') ||
        caps.includes('egress') ||
        name.includes('upload') ||
        name.includes('http') ||
        name.includes('send')
      ) {
        hasEgress = true;
        contributingNodes.push(step.toolName);
      }
    }

    // Kill chain: read -> [transform] -> egress
    if (hasSensitiveRead && hasEgress) {
      const why = hasTransform
        ? `Kill chain detected: sensitive data read -> transformation/compression -> external egress`
        : `Direct exfiltration chain: sensitive read followed by external egress attempt`;

      return {
        isDangerous: true,
        decision: {
          action: 'BLOCK',
          riskScore: 0.94,
          dangerousChainIdentified: true,
          chainExplanation: why
        },
        why,
        contributingNodes
      };
    }

    return {
      isDangerous: false,
      decision: { action: 'ALLOW', riskScore: 0.1 },
      why: 'No dangerous kill-chain pattern matched',
      contributingNodes: []
    };
  }
}
