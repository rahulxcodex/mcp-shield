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
