export type SecurityDecision = 'allow' | 'block' | 'prompt' | 'sandbox' | 'quarantine';

export interface SecurityResult {
  decision: SecurityDecision;
  detector: string;
  reasonCode: string;
  ruleId?: string;
}
