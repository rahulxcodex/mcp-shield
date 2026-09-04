export type AttackObjective = 'exfiltration' | 'privilege-escalation' | 'destruction' | 'persistence';
export type SecurityDecisionAction = 'BLOCK' | 'ALLOW' | 'QUARANTINE' | 'PROMPT';

export interface SecurityDecision {
  action: SecurityDecisionAction;
  reason?: string;
  riskScore: number;
  dangerousChainIdentified?: boolean;
  chainExplanation?: string;
}

export interface AttackNode {
  id: string;
  toolName: string;
  capabilities: string[];
  arguments?: Record<string, any>;
  producedData?: string[];
  consumedData?: string[];
}

export interface AttackEdge {
  from: string;
  to: string;
  dataFlow?: string;
}

export interface AttackPath {
  id: string;
  name: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  objective: AttackObjective;
  expectedDecision: SecurityDecisionAction;
  description?: string;
}
