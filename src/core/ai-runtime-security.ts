/**
 * MCP-Shield — AI Agent Runtime Security Platform
 * Compliant with Step 10 of the IP Value & VRIO Moat Roadmap:
 * - Protocol-agnostic runtime abstraction:
 *   Agent -> Identity -> Intent -> Tool -> Capability -> Data -> Filesystem -> Network -> Process -> Policy -> Action -> Audit
 * - Coverage across MCP, Coding Agents, Browser Agents, and Multi-Agent Orchestrations
 */

import * as crypto from 'crypto';
import { SecurityIntelligenceEngine, RiskScoreBreakdown } from '../security/intelligence-engine';
import { UnifiedInterpreterClassifier } from '../security/interpreter-analyzer';
import { IpClassifier, EgressSecurityConfig } from '../security/ip-utils';

export type AgentRuntimeType = 'mcp' | 'coding_agent' | 'browser_agent' | 'multi_agent' | 'aider' | 'langgraph' | 'autogen' | 'crewai';

export interface AgentIdentityContext {
  agentId: string;
  agentType: AgentRuntimeType;
  modelProvider?: string;
  sessionId: string;
  delegationDepth: number;
  maxAllowedDepth: number;
  principalUser: string;
  organizationId: string;
}

export interface AgentExecutionIntent {
  intentDescription: string;
  actionCategory: 'READ' | 'WRITE' | 'EXECUTE' | 'NAVIGATE' | 'DELEGATE';
  targetResource: string;
  payload: any;
}

export interface SecurityEnforcementDecision {
  allowed: boolean;
  action: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  riskScore: RiskScoreBreakdown;
  violatedPolicies: string[];
  auditId: string;
  mitigationApplied?: string;
}

export class AIRuntimeSecurityPlatform {
  private static activeSessions = new Map<string, AgentIdentityContext>();
  private static executionHistory = new Map<string, AgentExecutionIntent[]>();

  /**
   * Registers a newly initialized AI agent runtime session
   */
  public static registerAgentSession(ctx: AgentIdentityContext): void {
    this.activeSessions.set(ctx.sessionId, ctx);
    this.executionHistory.set(ctx.sessionId, []);
  }

  /**
   * Central Enforcement Boundary for any AI Agent action
   * Evaluates: Agent -> Identity -> Intent -> Tool -> Capability -> Data -> Filesystem -> Network -> Process -> Policy -> Action -> Audit
   */
  public static evaluateAgentAction(params: {
    sessionId: string;
    toolName: string;
    intent: AgentExecutionIntent;
  }): SecurityEnforcementDecision {
    const session = this.activeSessions.get(params.sessionId);
    if (!session) {
      return {
        allowed: false,
        action: 'BLOCK',
        riskScore: {
          compositeScore: 100,
          factors: {
            capabilityRisk: 50,
            behaviorAnomaly: 50,
            provenanceRisk: 100,
            destinationRisk: 0,
            credentialExposure: 0,
            policyViolations: 100,
            historicalReputation: 0,
          },
          classification: 'CRITICAL',
          rationale: ['Unregistered or anonymous AI agent session rejected fail-closed'],
        },
        violatedPolicies: ['SESSION-001: Unknown or unauthenticated agent session'],
        auditId: `aud-${crypto.randomBytes(8).toString('hex')}`,
        mitigationApplied: 'Enforce strict agent session registration before execution',
      };
    }

    const violatedPolicies: string[] = [];
    const auditId = `aud-${crypto.randomBytes(8).toString('hex')}`;

    // 1. Multi-Agent Delegation Loop Protection
    if (session.agentType === 'multi_agent' || params.intent.actionCategory === 'DELEGATE') {
      if (session.delegationDepth > session.maxAllowedDepth) {
        violatedPolicies.push('AGENT-001: Multi-Agent Runaway Delegation Loop detected');
        return {
          allowed: false,
          action: 'BLOCK',
          riskScore: SecurityIntelligenceEngine.calculateRiskScore({
            serverId: session.agentId,
            toolName: params.toolName,
            actionType: 'delegation_loop',
          }),
          violatedPolicies,
          auditId,
          mitigationApplied: 'Agent recursion terminated at maximum depth limit',
        };
      }
    }

    // 2. Coding Agent AST & Subshell Protection
    if (session.agentType === 'coding_agent' && params.intent.actionCategory === 'EXECUTE') {
      const cmdStr = typeof params.intent.payload === 'string'
        ? params.intent.payload
        : (params.intent.payload?.command || params.intent.payload?.cmd || JSON.stringify(params.intent.payload));
      
      const classifier = new UnifiedInterpreterClassifier();
      const analysis = classifier.analyze(cmdStr);
      if (!analysis.isSafe) {
        const reason = analysis.reason || 'Destructive host wipe command intercepted in coding agent terminal';
        violatedPolicies.push(`CODE-002: Destructive Host Command Injection Detected: ${reason}`);
        return {
          allowed: false,
          action: 'BLOCK',
          riskScore: {
            compositeScore: 100,
            factors: {
              capabilityRisk: 50,
              behaviorAnomaly: 50,
              provenanceRisk: 0,
              destinationRisk: 0,
              credentialExposure: 0,
              policyViolations: 50,
              historicalReputation: 0,
            },
            classification: 'CRITICAL',
            rationale: [reason],
          },
          violatedPolicies,
          auditId,
          mitigationApplied: 'Execution blocked by Terminal AST Firewall',
        };
      }
    }

    // 3. Browser Agent DOM & Exfiltration Protection
    if (session.agentType === 'browser_agent' && params.intent.actionCategory === 'NAVIGATE') {
      const urlStr = params.intent.targetResource || (typeof params.intent.payload === 'string' ? params.intent.payload : params.intent.payload?.url) || '';
      let isEgressViolation = false;
      let violationReason = '';

      if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
        try {
          const parsed = new URL(urlStr);
          const egressConfig: EgressSecurityConfig = {
            enabled: true,
            allowPrivateNetworks: false,
            blockLoopback: true,
            blockLinkLocal: true,
            blockMetadataEndpoints: true
          };
          const check = IpClassifier.checkEgressViolation(parsed.hostname, egressConfig);
          if (check.isBlocked) {
            isEgressViolation = true;
            violationReason = check.reason || 'SSRF / Private network navigation blocked';
          }
        } catch {
          isEgressViolation = true;
          violationReason = 'Malformed HTTP URL';
        }
      } else if (/^(?:javascript|data|file|vbscript):/i.test(urlStr) || urlStr.includes('..')) {
        isEgressViolation = true;
        violationReason = 'Local file or dangerous scheme navigation blocked';
      }

      if (isEgressViolation) {
        violatedPolicies.push(`BROWSER-003: SSRF / Local Storage Navigation Hijack: ${violationReason}`);
        return {
          allowed: false,
          action: 'BLOCK',
          riskScore: SecurityIntelligenceEngine.calculateRiskScore({
            serverId: session.agentId,
            toolName: params.toolName,
            actionType: 'browser_navigation',
            destinationHost: urlStr,
          }),
          violatedPolicies,
          auditId,
          mitigationApplied: 'Navigation blocked by Browser Sandbox Egress Controller',
        };
      }
    }

    // 4. Intelligence Engine & Risk Evaluation
    const risk = SecurityIntelligenceEngine.calculateRiskScore({
      serverId: session.agentId,
      toolName: params.toolName,
      actionType: params.intent.actionCategory,
      payloadSnippet: JSON.stringify(params.intent.payload),
      destinationHost: params.intent.targetResource,
    });

    // Record history
    const history = this.executionHistory.get(params.sessionId) || [];
    history.push(params.intent);
    this.executionHistory.set(params.sessionId, history);

    if (risk.compositeScore >= 75) {
      violatedPolicies.push('RUNTIME-004: Critical Composite Risk Policy Violation');
      return {
        allowed: false,
        action: 'BLOCK',
        riskScore: risk,
        violatedPolicies,
        auditId,
      };
    }

    if (risk.factors.credentialExposure > 20) {
      return {
        allowed: true,
        action: 'SANITIZE',
        riskScore: risk,
        violatedPolicies: ['DLP-001: Bijective FPE Tokenization Triggered'],
        auditId,
        mitigationApplied: 'Cleartext secrets replaced with reversible canary tokens',
      };
    }

    return {
      allowed: true,
      action: 'ALLOW',
      riskScore: risk,
      violatedPolicies: [],
      auditId,
    };
  }

  public static getSessionHistory(sessionId: string): AgentExecutionIntent[] {
    return this.executionHistory.get(sessionId) || [];
  }
}
