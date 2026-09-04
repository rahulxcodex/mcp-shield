import { AttackPath, AttackNode, SecurityDecision } from './attack-path-types';
import { ToxicFlowEngine, ToxicFlowViolation } from '../dataflow/toxic-flow-engine';

export interface ChainEvaluationResult {
  isDangerous: boolean;
  decision: SecurityDecision;
  why: string;
  contributingNodes: string[];
}

export class AttackPathEngine {
  private toxicFlowEngine = new ToxicFlowEngine();
  private callHistory: Array<{
    toolName: string;
    capabilities: string[];
    args: Record<string, any>;
    timestamp: number;
  }> = [];

  /**
   * Evaluates an in-flight tool invocation against the accumulated sequence history
   * utilizing true semantic toxic-flow data lineage tracking.
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

    const flowResult = this.toxicFlowEngine.evaluateStep(toolName, capabilities, args);
    if (flowResult.dangerousChainIdentified) {
      return {
        action: 'BLOCK',
        riskScore: flowResult.riskScore,
        dangerousChainIdentified: true,
        chainExplanation: `Kill chain detected: ${flowResult.chainExplanation || 'sensitive data read -> transformation/compression -> external egress'}`,
      };
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
    this.toxicFlowEngine.reset();
  }

  /**
   * Analyzes an explicit declarative AttackPath definition with semantic data lineage
   */
  public evaluateDeclarativePath(path: AttackPath): SecurityDecision {
    const res = this.toxicFlowEngine.evaluateDeclarativePath(path);
    return {
      action: res.action,
      riskScore: res.riskScore,
      dangerousChainIdentified: res.dangerousChainIdentified,
      chainExplanation: res.chainExplanation,
    };
  }

  /**
   * Direct access to underlying toxic-flow engine
   */
  public getToxicFlowEngine(): ToxicFlowEngine {
    return this.toxicFlowEngine;
  }
}
