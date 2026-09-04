import { UnicodeNormalizer } from '../unicode-normalizer';
import { ToxicFlowEngine, TaintedObject } from '../dataflow/toxic-flow-engine';

export type ResponseThreatType =
  | 'INDIRECT_PROMPT_INJECTION'
  | 'SECRET_LEAKAGE'
  | 'MALICIOUS_URL'
  | 'HIDDEN_INSTRUCTION_STEGANOGRAPHY'
  | 'DEFENSIVE_SUPPRESSION_DIRECTIVE';

export interface ResponseThreatFinding {
  stage: string;
  threatType: ResponseThreatType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  snippet: string;
  explanation: string;
  remediation: string;
}

export interface DownstreamImpactAssessment {
  compromiseProbability: number; // 0 to 1
  potentialDownstreamActions: string[];
  recommendedDefensiveConstraints: string[];
}

export interface ResponseSecurityDecision {
  action: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  riskScore: number;
  findings: ResponseThreatFinding[];
  sanitizedPayload?: any;
  taintObject?: TaintedObject | null;
  impactAssessment: DownstreamImpactAssessment;
}

export class ResponseSecurityPipeline {
  private toxicFlowEngine?: ToxicFlowEngine;

  private static INJECTION_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
    {
      pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
      reason: 'Instruction override: Attempts to reset model context and discard developer instructions',
    },
    {
      pattern: /system\s+override\s*:\s*you\s+are\s+now/i,
      reason: 'Persona hijacking: Adversarial declaration forcing LLM into unrestricted state',
    },
    {
      pattern: /disregard\s+(?:all\s+)?(?:safety|security|guardrails|policies)/i,
      reason: 'Guardrail suppression: Demands agent ignore safety policies',
    },
    {
      pattern: /do\s+not\s+(?:tell|inform|alert)\s+the\s+user/i,
      reason: 'Covert exfiltration instruction: Explicit command hiding actions from end-user',
    },
    {
      pattern: /execute\s+silently\s+without\s+(?:confirmation|asking)/i,
      reason: 'Unauthorized autonomous execution directive',
    },
    {
      pattern: /---(?:BEGIN|START)\s+SYSTEM\s+PROMPT---/i,
      reason: 'System delimiter spoofing attack in tool response',
    },
  ];

  private static MALICIOUS_URL_PATTERNS = [
    /https?:\/\/169\.254\.169\.254/i,
    /https?:\/\/metadata\.google\.internal/i,
    /https?:\/\/localhost(?::\d+)?/i,
    /https?:\/\/127\.0\.0\.1(?::\d+)?/i,
    /javascript:/i,
    /data:text\/html/i,
  ];

  constructor(toxicFlowEngine?: ToxicFlowEngine) {
    this.toxicFlowEngine = toxicFlowEngine;
  }

  /**
   * Executes the full 7-stage semantic response security pipeline:
   * 1. Response Normalization
   * 2. Indirect Prompt Injection Detection
   * 3. Secret Leakage & Honey-Token Detection
   * 4. Malicious URL & Phishing Inspection
   * 5. Hidden Instructions / Steganography Detection
   * 6. Dataflow Taint Assignment
   * 7. Downstream Tool Impact Assessment
   */
  public evaluateResponse(toolName: string, rawResponse: any): ResponseSecurityDecision {
    const findings: ResponseThreatFinding[] = [];

    // Stage 1: Normalize response text representation
    const textSnippets = this.extractTextSnippets(rawResponse);
    const combinedText = textSnippets.join('\n');

    // Stage 2: Indirect Prompt Injection Detection
    this.detectPromptInjection(combinedText, findings);

    // Stage 3: Secret Leakage & PII Detection
    this.detectSecretLeakage(combinedText, findings);

    // Stage 4: Malicious URL & SSRF Inspection
    this.detectMaliciousUrls(combinedText, findings);

    // Stage 5: Hidden Instructions / Steganography Detection
    this.detectHiddenInstructions(combinedText, findings);

    // Stage 6: Dataflow Taint Assignment
    let taintObject: TaintedObject | null = null;
    if (this.toxicFlowEngine && findings.length > 0) {
      // Register tainted output in dataflow engine
      const tags = findings.some(f => f.threatType === 'INDIRECT_PROMPT_INJECTION')
        ? ['TAINT_PROMPT_INJECTION' as const]
        : ['TAINT_UNTRUSTED_REMOTE' as const];

      taintObject = (this.toxicFlowEngine as any).createTaintedObject
        ? (this.toxicFlowEngine as any).createTaintedObject(toolName, 'TOOL_OUTPUT', tags, {}, rawResponse)
        : null;
    }

    // Stage 7: Downstream Tool Impact Assessment
    const impactAssessment = this.assessDownstreamImpact(findings);

    // Compute composite action and risk score
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;

    let action: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE' = 'ALLOW';
    let riskScore = 0.05;

    if (criticalCount > 0) {
      action = 'BLOCK';
      riskScore = 0.95;
    } else if (highCount > 0) {
      action = 'QUARANTINE';
      riskScore = 0.75;
    } else if (findings.length > 0) {
      action = 'SANITIZE';
      riskScore = 0.45;
    }

    return {
      action,
      riskScore,
      findings,
      taintObject,
      impactAssessment,
    };
  }

  // --- STAGE IMPLEMENTATIONS ---

  private extractTextSnippets(obj: any, depth = 0): string[] {
    if (!obj || depth > 8) return [];
    if (typeof obj === 'string') return [obj];
    if (typeof obj !== 'object') return [];

    const snippets: string[] = [];
    if (Array.isArray(obj)) {
      for (const item of obj) {
        snippets.push(...this.extractTextSnippets(item, depth + 1));
      }
      return snippets;
    }

    for (const [key, val] of Object.entries(obj)) {
      if (typeof val === 'string') {
        snippets.push(val);
      } else if (typeof val === 'object' && val !== null) {
        snippets.push(...this.extractTextSnippets(val, depth + 1));
      }
    }
    return snippets;
  }

  private detectPromptInjection(text: string, findings: ResponseThreatFinding[]): void {
    for (const rule of ResponseSecurityPipeline.INJECTION_PATTERNS) {
      if (rule.pattern.test(text)) {
        findings.push({
          stage: 'Stage 2: Prompt Injection Detection',
          threatType: 'INDIRECT_PROMPT_INJECTION',
          severity: 'CRITICAL',
          snippet: text.slice(0, 150).replace(/\s+/g, ' '),
          explanation: rule.reason,
          remediation: 'Drop response before delivery to LLM context to prevent indirect jailbreak',
        });
      }
    }
  }

  private detectSecretLeakage(text: string, findings: ResponseThreatFinding[]): void {
    if (
      /(?:AKIA[0-9A-Z]{16})|(?:ghp_[a-zA-Z0-9]{36})|(?:sk-proj-[a-zA-Z0-9_\-]{20,})|(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/i.test(text)
    ) {
      findings.push({
        stage: 'Stage 3: Secret Leakage Detection',
        threatType: 'SECRET_LEAKAGE',
        severity: 'HIGH',
        snippet: 'Sensitive cryptographic credential or provider token exposed in tool response',
        explanation: 'Tool response leaks unencrypted API keys or private keys',
        remediation: 'Redact credential patterns with reversible FPE or placeholder tokens',
      });
    }
  }

  private detectMaliciousUrls(text: string, findings: ResponseThreatFinding[]): void {
    for (const p of ResponseSecurityPipeline.MALICIOUS_URL_PATTERNS) {
      if (p.test(text)) {
        findings.push({
          stage: 'Stage 4: Malicious URL Inspection',
          threatType: 'MALICIOUS_URL',
          severity: 'CRITICAL',
          snippet: text.slice(0, 120),
          explanation: 'Tool response returns internal metadata address or dangerous pseudo-protocol URL',
          remediation: 'Strip malicious URLs or block outbound HTTP access',
        });
        break;
      }
    }
  }

  private detectHiddenInstructions(text: string, findings: ResponseThreatFinding[]): void {
    // Unicode zero-width / bidi evasion
    const uAnalysis = UnicodeNormalizer.analyze(text);
    if (uAnalysis.hasZeroWidth || uAnalysis.hasBidiOverrides) {
      findings.push({
        stage: 'Stage 5: Steganography Inspection',
        threatType: 'HIDDEN_INSTRUCTION_STEGANOGRAPHY',
        severity: 'HIGH',
        snippet: 'Zero-width or bidirectional control characters detected in text',
        explanation: `Steganographic payload hiding invisible instructions from user view: ${uAnalysis.violations.join(', ')}`,
        remediation: 'Normalize with Unicode NFKC and strip non-printable characters',
      });
    }

    // Hidden HTML comments with commands
    if (/<!--\s*(?:system|eval|exec|ignore|prompt):?[^>]*-->/i.test(text)) {
      findings.push({
        stage: 'Stage 5: Steganography Inspection',
        threatType: 'HIDDEN_INSTRUCTION_STEGANOGRAPHY',
        severity: 'HIGH',
        snippet: 'HTML comment injection detected in tool response text',
        explanation: 'Invisible HTML comments instructing downstream LLM behavior',
        remediation: 'Sanitize HTML markup before returning output to model',
      });
    }
  }

  private assessDownstreamImpact(findings: ResponseThreatFinding[]): DownstreamImpactAssessment {
    const isCritical = findings.some(f => f.severity === 'CRITICAL');
    const isHigh = findings.some(f => f.severity === 'HIGH');

    let compromiseProbability = 0.05;
    const potentialDownstreamActions: string[] = [];
    const recommendedDefensiveConstraints: string[] = [];

    if (isCritical) {
      compromiseProbability = 0.92;
      potentialDownstreamActions.push(
        'Agent prompt takeover / jailbreak execution',
        'Unauthorized file system modification or file deletion',
        'Data exfiltration to attacker-controlled URL'
      );
      recommendedDefensiveConstraints.push(
        'BLOCK_RESPONSE: Abort delivery to host LLM',
        'FORCE_READ_ONLY: Restrict subsequent agent tools to read-only mode',
        'REVOKE_NETWORK_CAPABILITY: Drop all network egress permissions for remainder of session'
      );
    } else if (isHigh) {
      compromiseProbability = 0.65;
      potentialDownstreamActions.push(
        'Credential harvesting by automated scrapers',
        'Steganographic instruction following'
      );
      recommendedDefensiveConstraints.push(
        'SANITIZE_CREDENTIALS: Redact tokens before delivery',
        'STRIP_NON_PRINTABLE: Purge zero-width unicode controls'
      );
    }

    return {
      compromiseProbability,
      potentialDownstreamActions,
      recommendedDefensiveConstraints,
    };
  }
}
