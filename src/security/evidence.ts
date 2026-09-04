/**
 * Universal Security Evidence Contract (Roadmap Section 11)
 *
 * Serves as the universal internal language and integration contract across:
 * - Deterministic detectors
 * - AST and interpreter analyzers
 * - Policy engine
 * - Attack-path and drift modeling
 * - Audit ledger and cloud telemetry
 */

export type ThreatCategory =
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'SSRF_EGRESS'
  | 'CREDENTIAL_EXFIL'
  | 'PRIVILEGE_ESCALATION'
  | 'PROTOCOL_VIOLATION'
  | 'DOS_AMPLIFICATION'
  | 'MALICIOUS_ATTACHMENT'
  | 'SCHEMA_POISONING'
  | 'UNTRUSTED_CAPABILITY'
  | 'SANDBOX_ESCAPE'
  | 'ANOMALOUS_BEHAVIOR';

export interface SecurityEvidence {
  /**
   * Unique identifier of the emitting detector/analyzer
   * e.g., 'ast-bash', 'path-security-resolver', 'powershell-analyzer', 'canary-tripwire'
   */
  detectorId: string;

  /**
   * Universal threat taxonomy category
   */
  category: ThreatCategory;

  /**
   * Normalized risk severity between 0.0 (info/benign) and 1.0 (critical threat)
   */
  severity: number;

  /**
   * Detector confidence score between 0.0 and 1.0
   */
  confidence: number;

  /**
   * If true, this evidence demands an immediate fail-closed block regardless of composite risk score
   */
  hardBlock: boolean;

  /**
   * Machine-readable extracted features for attack chaining and audit logging
   */
  features: Record<string, number | string | boolean>;

  /**
   * Human and LLM readable explanation of the violation
   */
  explanation: string;

  /**
   * Optional parameter path or lexical location where violation occurred (e.g. 'params.arguments.command')
   */
  location?: string;
}

/**
 * Backward compatibility helper to convert legacy Evidence to canonical SecurityEvidence
 */
export function toSecurityEvidence(
  detectorId: string,
  finding: string,
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
  category: ThreatCategory = 'ANOMALOUS_BEHAVIOR'
): SecurityEvidence {
  const severityMap: Record<string, number> = {
    LOW: 0.25,
    MEDIUM: 0.5,
    HIGH: 0.75,
    CRITICAL: 1.0
  };

  const severity = severityMap[risk] ?? 0.5;
  return {
    detectorId,
    category,
    severity,
    confidence: 1.0,
    hardBlock: risk === 'CRITICAL' || risk === 'HIGH',
    features: { legacyRisk: risk },
    explanation: finding
  };
}
