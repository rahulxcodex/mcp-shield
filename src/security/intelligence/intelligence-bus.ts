import { SecurityDecisionAction, EnforcementSource, BayesianDecisionEngine } from '../decision';

export type SignalScope = 'request' | 'session' | 'tool' | 'server' | 'organization';

export interface SecuritySignal {
  signalId: string;
  source: string;
  category: string;
  severity: number; // 0.0 to 1.0
  confidence: number; // 0.0 to 1.0
  timestamp: number;
  scope: SignalScope;
  evidence: Record<string, unknown>;
  hardBlockCandidate?: boolean;
}

export interface FusedIntelligenceReport {
  recommendedAction: SecurityDecisionAction;
  compositeRiskScore: number;
  confidence: number;
  enforcementSource: EnforcementSource;
  primarySignals: SecuritySignal[];
  rationale: string[];
  deterministicBlockTriggered: boolean;
}

export type SignalSubscriber = (signal: SecuritySignal) => void;

/**
 * Enterprise Security Intelligence Bus (Roadmap Section 7.2)
 * Decouples signal generation from pipeline policy evaluation.
 * Combines typed signals across detectors, attack-path models, and ML scoring
 * using deterministic precedence invariants.
 */
export class SecurityIntelligenceBus {
  private subscribers: Map<string, Set<SignalSubscriber>> = new Map();
  private signalBuffer: SecuritySignal[] = [];
  private maxBufferSize: number = 1000;

  public publish(signal: SecuritySignal): void {
    this.signalBuffer.push(signal);
    if (this.signalBuffer.length > this.maxBufferSize) {
      this.signalBuffer.shift();
    }

    // Notify specific category subscribers
    const catSubs = this.subscribers.get(signal.category);
    if (catSubs) {
      for (const sub of catSubs) {
        try {
          sub(signal);
        } catch {
          // Prevent subscriber errors from disrupting the bus
        }
      }
    }

    // Notify global wildcard subscribers
    const wildcardSubs = this.subscribers.get('*');
    if (wildcardSubs) {
      for (const sub of wildcardSubs) {
        try {
          sub(signal);
        } catch {
          // Ignore
        }
      }
    }
  }

  public subscribe(category: string, subscriber: SignalSubscriber): () => void {
    if (!this.subscribers.has(category)) {
      this.subscribers.set(category, new Set());
    }
    this.subscribers.get(category)!.add(subscriber);

    return () => {
      this.subscribers.get(category)?.delete(subscriber);
    };
  }

  public getSignals(scope?: SignalScope): SecuritySignal[] {
    if (!scope) return [...this.signalBuffer];
    return this.signalBuffer.filter((s) => s.scope === scope);
  }

  public clear(): void {
    this.signalBuffer = [];
  }

  /**
   * Deterministic Signal Fusion Engine (Roadmap Section 7.2 & 7.4)
   * Enforces strict hierarchy:
   * 1. Deterministic hard blocks (AST, DLP, Path, SSRF) -> Unconditional BLOCK
   * 2. Attack Graph kill chains -> BLOCK / SANDBOX
   * 3. ML Risk & Novelty -> Advisory PROMPT / MONITOR / ALLOW (Cannot override hard block)
   */
  public static fuseSignals(signals: SecuritySignal[]): FusedIntelligenceReport {
    if (signals.length === 0) {
      return {
        recommendedAction: 'ALLOW',
        compositeRiskScore: 0.0,
        confidence: 1.0,
        enforcementSource: 'deterministic',
        primarySignals: [],
        rationale: ['Zero security signals emitted. Benign tool action.'],
        deterministicBlockTriggered: false
      };
    }

    const rationale: string[] = [];
    const primarySignals: SecuritySignal[] = [];

    // 1. Check for Deterministic Hard Blocks
    const hardBlocks = signals.filter(
      (s) => s.hardBlockCandidate || (s.severity >= 0.85 && s.confidence >= 0.90 && s.source.startsWith('deterministic'))
    );

    if (hardBlocks.length > 0) {
      for (const hb of hardBlocks) {
        rationale.push(`DETERMINISTIC HARD BLOCK by ${hb.source} [${hb.category}]: severity ${hb.severity}`);
        primarySignals.push(hb);
      }

      return {
        recommendedAction: 'BLOCK',
        compositeRiskScore: 1.0,
        confidence: 1.0,
        enforcementSource: 'deterministic',
        primarySignals,
        rationale,
        deterministicBlockTriggered: true
      };
    }

    // 2. Check for Attack-Path Multi-Tool Kill Chains
    const attackPathSignals = signals.filter((s) => s.category === 'ATTACK_PATH' || s.category === 'KILL_CHAIN');
    if (attackPathSignals.length > 0 && attackPathSignals.some((s) => s.severity >= 0.8)) {
      const killer = attackPathSignals.find((s) => s.severity >= 0.8)!;
      rationale.push(`Attack graph kill-chain detected by ${killer.source}: ${JSON.stringify(killer.evidence)}`);
      primarySignals.push(killer);

      return {
        recommendedAction: 'BLOCK',
        compositeRiskScore: killer.severity,
        confidence: killer.confidence,
        enforcementSource: 'composite',
        primarySignals,
        rationale,
        deterministicBlockTriggered: false
      };
    }

    // 3. Composite ML & Behavioral Fusion (Advisory-First using Bayesian Evidence Combination)
    const compositeRisk = BayesianDecisionEngine.calculatePosteriorRisk(signals);
    let confidenceSum = 0.0;

    for (const sig of signals) {
      confidenceSum += sig.confidence;
      if (sig.severity >= 0.4) {
        primarySignals.push(sig);
        rationale.push(`${sig.source} flagged ${sig.category} (severity: ${sig.severity}, confidence: ${sig.confidence})`);
      }
    }

    const avgConfidence = signals.length > 0 ? Number((confidenceSum / signals.length).toFixed(2)) : 1.0;

    // Multi-Attribute Utility Optimization
    const action = BayesianDecisionEngine.optimizeAction(compositeRisk, avgConfidence, false);
    const source: EnforcementSource = compositeRisk >= 0.75 ? 'composite' : 'ml';

    return {
      recommendedAction: action,
      compositeRiskScore: compositeRisk,
      confidence: avgConfidence,
      enforcementSource: source,
      primarySignals,
      rationale: rationale.length > 0 ? rationale : ['All evaluated signals within normal threshold.'],
      deterministicBlockTriggered: false
    };
  }
}
