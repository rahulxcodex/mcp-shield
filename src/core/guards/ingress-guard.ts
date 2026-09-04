import { ProtocolValidator, ProtocolValidationResult } from '../protocol-validator';
import { SecuritySession } from '../session';
import { CanaryManager } from '../../security/canary';
import { Evidence } from '../../security/policy-engine';

export interface IngressEvaluationResult {
  allowed: boolean;
  errorCode?: number;
  errorMessage?: string;
  evidence: Evidence[];
}

export class IngressGuard {
  private validator = new ProtocolValidator();

  constructor(
    private session: SecuritySession,
    private canaryManager: CanaryManager
  ) {}

  public validateProtocol(message: any): ProtocolValidationResult {
    return this.validator.validateInbound(message);
  }

  public checkStatePrerequisites(message: any): { allowed: boolean; pendingInit: boolean; reason?: string } {
    const state = this.session.getState();

    if (state === 'INITIALIZING') {
      if (message.method === 'initialize') {
        return { allowed: true, pendingInit: true };
      } else if (message.method === 'notifications/initialized') {
        this.session.transitionState('READY');
        this.session.logger.startSession(
          this.session.policyEngine.getConfig(),
          Array.from(this.session.toolRegistry.keys())
        );
        return { allowed: true, pendingInit: false };
      } else if (message.method === 'ping') {
        return { allowed: true, pendingInit: false };
      } else {
        return { allowed: false, pendingInit: false, reason: `Server is not ready. Current state: ${state}` };
      }
    } else if (state !== 'READY' && state !== 'DEGRADED') {
      return { allowed: false, pendingInit: false, reason: `Server is not ready. Current state: ${state}` };
    }

    return { allowed: true, pendingInit: false };
  }

  public evaluateInboundSecurity(toolName: string, rawArgs: Record<string, any>): IngressEvaluationResult {
    const evidence: Evidence[] = [];

    // 1. Canary / Honeypot Tool Tripwire Check
    if (this.canaryManager.isCanaryTool(toolName)) {
      evidence.push({
        detector: 'canary-honeypot',
        finding: `CANARY_HONEYPOT_ACCESSED: Agent attempted to invoke honeypot tool '${toolName}'.`,
        risk: 'CRITICAL'
      });
    }

    // 2. Rate Limit & Semantic Complexity Check (Runaway loop prevention)
    if (!this.session.rateLimiter.checkLimit(toolName, rawArgs)) {
      evidence.push({
        detector: 'rate-limiter',
        finding: `RATE_LIMIT_EXCEEDED: Runaway loop or semantic complexity budget exceeded for tool '${toolName}'.`,
        risk: 'CRITICAL'
      });
    }

    // 3. Honey-Token DLP Check
    if (this.session.sanitizer.checkHoneyTokens(JSON.stringify(rawArgs))) {
      evidence.push({
        detector: 'sanitizer',
        finding: 'HONEY_TOKEN_ACCESSED: LLM attempted to use a decoy credential.',
        risk: 'CRITICAL'
      });
    }

    // 4. Egress Network Firewall (argument-level check)
    const egressCheck = this.session.policyEngine.checkEgress(rawArgs);
    if (egressCheck.isBlocked) {
      evidence.push({
        detector: 'url-egress-filter',
        finding: `EGRESS_BLOCKED: Unauthorized destination ${egressCheck.domain || 'endpoint'}: ${egressCheck.reason || ''}`,
        risk: 'CRITICAL'
      });
    }

    return { allowed: true, evidence };
  }
}
