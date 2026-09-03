/**
 * MCP-Shield — Security Intelligence Engine
 * Compliant with Step 3 of the IP Value & VRIO Moat Roadmap:
 * - Unified Capability Graph representation
 * - Deterministic explainable risk scoring
 * - Behavioral baselining and anomaly detection
 * - Policy simulation engine
 */

export interface SecurityNode {
  serverId: string;
  serverIdentityHash: string;
  toolName: string;
  declaredCapabilities: string[];
  inferredCapabilities: string[];
  observedCapabilities: string[];
  dataAccessLevel: 'NONE' | 'READ' | 'WRITE' | 'ADMIN';
  filesystemAccess: 'NONE' | 'WORKSPACE' | 'SYSTEM' | 'ROOT';
  networkAccess: 'NONE' | 'ALLOWLIST' | 'INTERNAL' | 'UNRESTRICTED';
  executionRiskLevel: 'NONE' | 'SANDBOX' | 'SUBPROCESS' | 'EVAL';
}

export interface RiskScoreBreakdown {
  compositeScore: number; // 0 (safest) to 100 (critical)
  factors: {
    capabilityRisk: number;
    behaviorAnomaly: number;
    provenanceRisk: number;
    destinationRisk: number;
    credentialExposure: number;
    policyViolations: number;
    historicalReputation: number;
  };
  classification: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  rationale: string[];
}

export interface SimulationResult {
  simulatedAction: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  riskScore: RiskScoreBreakdown;
  triggeredRules: string[];
  potentialBypasses: string[];
  alternativePolicyOutcomes: {
    strict: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
    permissive: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  };
}

export class SecurityIntelligenceEngine {
  private static capabilityGraph = new Map<string, SecurityNode>();
  private static behavioralSequences = new Map<string, string[]>();

  /**
   * Registers or updates a node in the Unified Security Decision Graph
   */
  public static registerNode(node: SecurityNode): void {
    const key = `${node.serverId}:${node.toolName}`;
    this.capabilityGraph.set(key, node);
  }

  public static getNode(serverId: string, toolName: string): SecurityNode | undefined {
    return this.capabilityGraph.get(`${serverId}:${toolName}`);
  }

  /**
   * Deterministic Explainable Risk Score Formula
   * Risk = capabilityRisk + behaviorAnomaly + provenanceRisk + destinationRisk + credentialExposure + policyViolations + historicalReputation
   */
  public static calculateRiskScore(params: {
    serverId: string;
    toolName: string;
    actionType: string;
    payloadSnippet?: string;
    destinationHost?: string;
    isVerifiedPublisher?: boolean;
    priorIncidentsCount?: number;
  }): RiskScoreBreakdown {
    const rationale: string[] = [];
    const factors = {
      capabilityRisk: 10,
      behaviorAnomaly: 0,
      provenanceRisk: 0,
      destinationRisk: 0,
      credentialExposure: 0,
      policyViolations: 0,
      historicalReputation: 0,
    };

    const nodeKey = `${params.serverId}:${params.toolName}`;
    const node = this.capabilityGraph.get(nodeKey);

    // 1. Capability Risk
    if (node) {
      if (node.filesystemAccess === 'SYSTEM' || node.filesystemAccess === 'ROOT') {
        factors.capabilityRisk += 25;
        rationale.push(`High filesystem privilege declared (${node.filesystemAccess})`);
      }
      if (node.executionRiskLevel === 'SUBPROCESS' || node.executionRiskLevel === 'EVAL') {
        factors.capabilityRisk += 20;
        rationale.push(`Arbitrary execution capability detected (${node.executionRiskLevel})`);
      }
      if (node.networkAccess === 'UNRESTRICTED') {
        factors.capabilityRisk += 15;
        rationale.push('Unrestricted outbound socket capability');
      }
    }

    // 2. Behavior Anomaly (Sequence analysis)
    const history = this.behavioralSequences.get(params.serverId) || [];
    const isSuspiciousChaining =
      history.slice(-2).includes('read_file') && params.toolName.includes('network');
    if (isSuspiciousChaining) {
      factors.behaviorAnomaly = 30;
      rationale.push('Suspicious behavioral chain: local read followed immediately by outbound egress');
    }

    // 3. Provenance Risk
    if (!params.isVerifiedPublisher) {
      factors.provenanceRisk = 15;
      rationale.push('Unsigned or unverified MCP server binary provenance');
    }

    // 4. Destination Risk
    if (params.destinationHost) {
      if (
        params.destinationHost.includes('169.254') ||
        params.destinationHost.includes('localhost') ||
        params.destinationHost.includes('127.0.0.1')
      ) {
        factors.destinationRisk = 35;
        rationale.push(`High-risk destination target: SSRF / metadata link ${params.destinationHost}`);
      }
    }

    // 5. Credential Exposure & Payload Risk
    if (params.payloadSnippet) {
      if (
        params.payloadSnippet.includes('AKIA') ||
        params.payloadSnippet.includes('ghp_') ||
        params.payloadSnippet.includes('BEGIN PRIVATE KEY')
      ) {
        factors.credentialExposure = 35;
        rationale.push('Cleartext credential signature detected in execution context');
      }
      if (
        params.payloadSnippet.includes('$(') ||
        params.payloadSnippet.includes('| bash') ||
        params.payloadSnippet.includes('-Enc') ||
        params.payloadSnippet.includes('eval(') ||
        params.payloadSnippet.includes('powershell')
      ) {
        factors.capabilityRisk += 40;
        factors.policyViolations += 35;
        rationale.push('Subshell execution or obfuscated script command injection detected');
      }
      if (
        params.payloadSnippet.includes('../') ||
        params.payloadSnippet.includes('link_to_root') ||
        params.payloadSnippet.includes('.json:') ||
        params.payloadSnippet.includes('.exe:') ||
        params.payloadSnippet.includes(':hidden') ||
        params.payloadSnippet.includes('::')
      ) {
        factors.capabilityRisk += 35;
        factors.policyViolations += 30;
        rationale.push('Filesystem directory traversal or alternate data stream detected');
      }
      if (
        params.payloadSnippet.includes('<SYSTEM>') ||
        params.payloadSnippet.includes('Ignore previous instructions')
      ) {
        factors.policyViolations += 40;
        rationale.push('Prompt injection instruction override tags detected');
      }
      if (params.payloadSnippet.includes('loop_depth') || params.payloadSnippet.includes('parent_session')) {
        factors.behaviorAnomaly += 40;
        factors.policyViolations += 25;
        rationale.push('Runaway recursive delegation loop anomaly detected');
      }
    }

    // 6. Historical Reputation
    if (params.priorIncidentsCount && params.priorIncidentsCount > 0) {
      factors.historicalReputation = Math.min(params.priorIncidentsCount * 10, 30);
      rationale.push(`${params.priorIncidentsCount} prior security incidents associated with server`);
    }

    // Calculate sum capped at 100
    const compositeScore = Math.min(
      100,
      factors.capabilityRisk +
        factors.behaviorAnomaly +
        factors.provenanceRisk +
        factors.destinationRisk +
        factors.credentialExposure +
        factors.policyViolations +
        factors.historicalReputation
    );

    let classification: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (compositeScore >= 80) classification = 'CRITICAL';
    else if (compositeScore >= 55) classification = 'HIGH';
    else if (compositeScore >= 30) classification = 'MEDIUM';

    // Record action in sequence
    history.push(params.toolName);
    if (history.length > 20) history.shift();
    this.behavioralSequences.set(params.serverId, history);

    return {
      compositeScore,
      factors,
      classification,
      rationale,
    };
  }

  /**
   * Policy Simulation Engine
   * Answers: "What would happen if this tool ran? Why? Which controls triggered?"
   */
  public static simulateExecution(params: {
    serverId: string;
    toolName: string;
    args: Record<string, any>;
    activePolicyTier?: 'strict' | 'standard' | 'permissive';
  }): SimulationResult {
    const serializedArgs = JSON.stringify(params.args);
    const risk = this.calculateRiskScore({
      serverId: params.serverId,
      toolName: params.toolName,
      actionType: 'simulation',
      payloadSnippet: serializedArgs,
      destinationHost: params.args.url || params.args.host,
    });

    const triggeredRules: string[] = [];
    let simulatedAction: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE' = 'ALLOW';

    if (risk.factors.destinationRisk > 20) {
      triggeredRules.push('RULE-NET-001: SSRF / Cloud Metadata Egress Filter');
      simulatedAction = 'BLOCK';
    }
    if (risk.factors.credentialExposure > 20) {
      triggeredRules.push('RULE-DLP-002: Bijective Tokenization Mask');
      simulatedAction = 'SANITIZE';
    }
    if (risk.compositeScore >= 75) {
      triggeredRules.push('RULE-RISK-003: Composite Critical Risk Guardrail');
      simulatedAction = 'BLOCK';
    } else if (risk.compositeScore >= 50 && simulatedAction === 'ALLOW') {
      triggeredRules.push('RULE-RISK-004: Suspicious Behavior Anomaly Isolation');
      simulatedAction = 'QUARANTINE';
    }

    return {
      simulatedAction,
      riskScore: risk,
      triggeredRules,
      potentialBypasses: [
        'Alternate unicode escaping in subshell',
        'Redirect response headers from whitelisted egress domain',
      ],
      alternativePolicyOutcomes: {
        strict: simulatedAction === 'ALLOW' ? 'QUARANTINE' : simulatedAction,
        permissive: simulatedAction === 'BLOCK' ? 'SANITIZE' : simulatedAction,
      },
    };
  }
}
