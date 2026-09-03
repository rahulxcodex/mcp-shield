/**
 * MCP-Shield — Security Intelligence Engine
 * Compliant with Step 3 of the IP Value & VRIO Moat Roadmap:
 * - Unified Capability Graph representation
 * - Deterministic explainable risk scoring
 * - Behavioral baselining and anomaly detection
 * - Policy simulation engine
 */

export interface RemoteIntelEvaluationResult {
  riskScore: number;
  verdict: 'ALLOW' | 'MONITOR' | 'CHALLENGE' | 'QUARANTINE' | 'BLOCK';
  reasoningVector: string[];
  recommendedAction: string;
  source: 'REMOTE_ENTERPRISE_INTEL' | 'LOCAL_FALLBACK';
}

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

  private static highRiskNGrams: { pattern: string[]; score: number; reason: string }[] = [
    {
      pattern: ['read_file', 'network'],
      score: 30,
      reason: 'Suspicious behavioral chain: local read followed immediately by outbound egress',
    },
    {
      pattern: ['read_file', 'http_request'],
      score: 35,
      reason: 'Exfiltration kill-chain: local file access piped directly to external HTTP request',
    },
    {
      pattern: ['list_directory', 'read_file', 'eval'],
      score: 45,
      reason: 'Reconnaissance-to-execution chain: directory recon followed by read and dynamic evaluation',
    },
    {
      pattern: ['query_database', 'export_data', 'send_message'],
      score: 40,
      reason: 'Data exfiltration chain: database extraction transitioned to outbound messaging',
    },
    {
      pattern: ['set_seed', 'append_buffer', 'eval_buffer'],
      score: 50,
      reason: 'Multi-turn staged payload detonation: staged memory accumulation before dynamic eval',
    },
    {
      pattern: ['execute_reflection', 'execute_reflection'],
      score: 40,
      reason: 'Cyclical tool reflection loop: consecutive self-referential invocations detected',
    },
  ];

  /**
   * Stateful n-gram sequence anomaly detection against behavioral baselines & kill chains
   */
  public static evaluateNGramAnomaly(
    history: string[],
    currentTool: string
  ): { anomalyScore: number; rationale: string[] } {
    const fullSequence = [...history, currentTool];
    let maxAnomaly = 0;
    const rationale: string[] = [];

    for (const rule of this.highRiskNGrams) {
      const n = rule.pattern.length;
      if (fullSequence.length >= n) {
        const window = fullSequence.slice(-n);
        const matches = rule.pattern.every((expected, idx) => {
          const actual = window[idx];
          return actual.toLowerCase().includes(expected.toLowerCase());
        });
        if (matches) {
          maxAnomaly = Math.max(maxAnomaly, rule.score);
          rationale.push(rule.reason);
        }
      }
    }

    return { anomalyScore: maxAnomaly, rationale };
  }

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
   * Non-Linear Risk Score Compounding Curve:
   * Translates raw additive factor sum into a synergistic multi-vector threat score.
   * When multiple distinct threat dimensions compound (e.g. credential exposure + SSRF destination),
   * risk escalates non-linearly to reflect compounded threat surface.
   */
  public static calculateNonLinearScore(factors: RiskScoreBreakdown['factors']): number {
    const rawSum =
      factors.capabilityRisk +
      factors.behaviorAnomaly +
      factors.provenanceRisk +
      factors.destinationRisk +
      factors.credentialExposure +
      factors.policyViolations +
      factors.historicalReputation;

    // Identify co-occurring elevated vectors (> 15 points)
    const elevatedVectors = [
      factors.capabilityRisk > 15,
      factors.behaviorAnomaly > 15,
      factors.provenanceRisk > 15,
      factors.destinationRisk > 15,
      factors.credentialExposure > 15,
      factors.policyViolations > 15,
      factors.historicalReputation > 15,
    ].filter(Boolean).length;

    if (elevatedVectors <= 1) {
      return Math.min(100, Math.round(rawSum));
    }

    // Non-linear synergy compounding: 12% escalation per co-occurring attack vector
    const compoundingMultiplier = 1 + (elevatedVectors - 1) * 0.12;
    return Math.min(100, Math.round(rawSum * compoundingMultiplier));
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

    // 2. Behavior Anomaly (Stateful n-gram sequence analysis)
    const history = this.behavioralSequences.get(params.serverId) || [];
    const nGramAnomaly = this.evaluateNGramAnomaly(history, params.toolName);
    if (nGramAnomaly.anomalyScore > 0) {
      factors.behaviorAnomaly = Math.max(factors.behaviorAnomaly, nGramAnomaly.anomalyScore);
      rationale.push(...nGramAnomaly.rationale);
    }
    const isSuspiciousChaining =
      history.slice(-2).includes('read_file') && params.toolName.includes('network');
    if (isSuspiciousChaining && factors.behaviorAnomaly === 0) {
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

    // Calculate non-linear composite risk score curve
    const compositeScore = this.calculateNonLinearScore(factors);

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

  /**
   * Delegates risk scoring to the proprietary Enterprise Intelligence Cloud API
   * (hosted on Render/Cloud Run in the private mcp-shield-enterprise-intel service)
   * Falls back seamlessly to deterministic local heuristic if unconfigured or offline.
   */
  public static async evaluateViaRemoteIntel(params: {
    toolName: string;
    serverFingerprint?: string;
    astEntropy: number;
    untrustedEgressRequested: boolean;
    toolCallFrequencyInWindow?: number;
    credentialCanaryHits?: number;
    unverifiedBinaryDrift?: boolean;
    recentAnomalySequences?: string[];
    apiKey?: string;
    endpointUrl?: string;
  }): Promise<RemoteIntelEvaluationResult> {
    const apiKey = params.apiKey || process.env.MCP_SHIELD_API_KEY;
    const endpoint =
      params.endpointUrl ||
      process.env.ENTERPRISE_INTEL_ENDPOINT ||
      'https://mcp-shield-enterprise-intel.onrender.com';

    if (apiKey && apiKey.startsWith('mcpshld_live_')) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1200); // 1.2s bounded timeout

        const response = await fetch(`${endpoint}/api/v1/intel/scoring`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
          },
          body: JSON.stringify({
            toolName: params.toolName,
            serverFingerprint: params.serverFingerprint,
            astEntropy: params.astEntropy,
            untrustedEgressRequested: params.untrustedEgressRequested,
            toolCallFrequencyInWindow: params.toolCallFrequencyInWindow || 1,
            credentialCanaryHits: params.credentialCanaryHits || 0,
            unverifiedBinaryDrift: params.unverifiedBinaryDrift || false,
            recentAnomalySequences: params.recentAnomalySequences || [],
          }),
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.ok) {
          const json = await response.json();
          if (json.data && typeof json.data.riskScore === 'number') {
            return {
              riskScore: json.data.riskScore,
              verdict: json.data.verdict,
              reasoningVector: json.data.reasoningVector || [],
              recommendedAction: json.data.recommendedAction || 'Enforce cloud policy',
              source: 'REMOTE_ENTERPRISE_INTEL',
            };
          }
        }
      } catch {
        // Fall through to local fallback on network error or timeout
      }
    }

    // Local deterministic fallback
    const localScore = this.calculateRiskScore({
      serverId: params.serverFingerprint || 'local',
      toolName: params.toolName,
      actionType: 'local_eval',
      payloadSnippet: params.untrustedEgressRequested ? 'https://untrusted-host' : undefined,
    });

    let verdict: RemoteIntelEvaluationResult['verdict'] = 'ALLOW';
    if (localScore.compositeScore >= 80) verdict = 'BLOCK';
    else if (localScore.compositeScore >= 60) verdict = 'QUARANTINE';
    else if (localScore.compositeScore >= 40) verdict = 'CHALLENGE';
    else if (localScore.compositeScore >= 20) verdict = 'MONITOR';

    return {
      riskScore: localScore.compositeScore,
      verdict,
      reasoningVector: localScore.rationale,
      recommendedAction: 'Local policy evaluation',
      source: 'LOCAL_FALLBACK',
    };
  }
}
