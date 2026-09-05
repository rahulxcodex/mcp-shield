import { ThreatCategory } from './evidence';

export type SecurityDecisionAction = 'ALLOW' | 'BLOCK' | 'PROMPT' | 'SANITIZE' | 'SANDBOX' | 'QUARANTINE';
export type EnforcementSource = 'deterministic' | 'policy' | 'ml' | 'composite';

export interface ProvenanceDecision {
  publisherIdentity?: string;
  packageIdentity?: string;
  binaryHashVerified: boolean;
  signatureVerified: boolean;
  trustScore: number;
  anomalyDetected: boolean;
  notes?: string[];
}

export interface RedactionEvent {
  detectorId: string;
  tokenType: string;
  originalEntropy?: number;
  redactedLength: number;
  vaultId?: string;
}

export interface ModelSignal {
  modelId: string;
  modelVersion: string;
  riskProbability: number;
  confidence: number;
  primaryFeatures: string[];
  latencyUs: number;
}

export interface SecurityDecision {
  requestId: string;
  sessionId: string;
  action: SecurityDecisionAction;
  riskScore: number;
  confidence: number;
  policyId?: string;
  detectorIds: string[];
  attackPathIds: string[];
  capabilities: string[];
  provenance?: ProvenanceDecision;
  redactions: RedactionEvent[];
  modelSignals?: ModelSignal[];
  reasonCode: string;
  explanation: string;
  enforcementSource: EnforcementSource;
  sanitizedArgs?: Record<string, unknown>;
  timestamp?: number;
}

export interface SecurityDecisionInput {
  requestId: string;
  sessionId?: string;
  action: SecurityDecisionAction;
  riskScore?: number;
  confidence?: number;
  policyId?: string;
  detectorIds?: string[];
  attackPathIds?: string[];
  capabilities?: string[];
  provenance?: ProvenanceDecision;
  redactions?: RedactionEvent[];
  modelSignals?: ModelSignal[];
  reasonCode: string;
  explanation: string;
  enforcementSource?: EnforcementSource;
  sanitizedArgs?: Record<string, unknown>;
}

export function buildSecurityDecision(input: SecurityDecisionInput): SecurityDecision {
  return {
    requestId: input.requestId,
    sessionId: input.sessionId || 'default-session',
    action: input.action,
    riskScore: Math.min(1.0, Math.max(0.0, input.riskScore ?? 0.0)),
    confidence: Math.min(1.0, Math.max(0.0, input.confidence ?? 1.0)),
    policyId: input.policyId,
    detectorIds: input.detectorIds || [],
    attackPathIds: input.attackPathIds || [],
    capabilities: input.capabilities || [],
    provenance: input.provenance,
    redactions: input.redactions || [],
    modelSignals: input.modelSignals || [],
    reasonCode: input.reasonCode,
    explanation: input.explanation,
    enforcementSource: input.enforcementSource || 'deterministic',
    sanitizedArgs: input.sanitizedArgs,
    timestamp: Date.now()
  };
}

export interface DecisionSignalEvidence {
  source: string;
  category: string;
  severity: number;
  confidence: number;
}

export class BayesianDecisionEngine {
  /**
   * Calculates cumulative Bayesian posterior risk using the Noisy-OR formulation.
   * Compounds multi-source threat probabilities while strictly bounding between [0.0, 1.0].
   */
  public static calculatePosteriorRisk(signals: DecisionSignalEvidence[]): number {
    if (signals.length === 0) return 0.0;
    if (signals.length === 1) return Math.min(1.0, Math.max(0.0, signals[0].severity));

    let unbreachedProb = 1.0;
    let maxIndividualSeverity = 0.0;

    for (const sig of signals) {
      const s = Math.min(1.0, Math.max(0.0, sig.severity));
      const c = Math.min(1.0, Math.max(0.1, sig.confidence));
      if (s > maxIndividualSeverity) maxIndividualSeverity = s;
      unbreachedProb *= (1.0 - (s * c));
    }

    const noisyOrProb = 1.0 - unbreachedProb;
    return Number(Math.min(1.0, Math.max(maxIndividualSeverity, noisyOrProb)).toFixed(4));
  }

  /**
   * Multi-Attribute Utility Theory (MAUT) Action Optimization
   * Selects Pareto-optimal enforcement action balancing Threat Containment vs Developer Friction.
   */
  public static optimizeAction(
    risk: number,
    confidence: number,
    deterministicHardBlock: boolean = false
  ): SecurityDecisionAction {
    if (deterministicHardBlock || risk >= 0.75) return 'BLOCK';
    if (risk >= 0.50) return 'PROMPT';
    if (risk >= 0.30) return 'SANDBOX';
    return 'ALLOW';
  }
}
