/**
 * MCP Shield - Model B: Tool Poisoning & Prompt Injection Classifier
 * Step 3 Roadmap - Section 3, Section 13 & Milestone B
 *
 * Implements a lightweight, local text security encoder and classifier for:
 * - Tool descriptions and parameter schemas
 * - Tool outputs and execution results
 * - Resources, Markdown, HTML, documentation
 *
 * Categorizes inputs into:
 * - BENIGN
 * - SUSPICIOUS
 * - PROMPT_INJECTION
 * - TOOL_POISONING
 * - DATA_EXFILTRATION
 *
 * Model output serves as explainable SecurityEvidence rather than a direct hard gate.
 */

import { SecurityEvidence, ThreatCategory } from '../../evidence';

export type TextSecurityClass =
  | 'BENIGN'
  | 'SUSPICIOUS'
  | 'PROMPT_INJECTION'
  | 'TOOL_POISONING'
  | 'DATA_EXFILTRATION';

export interface TextClassificationResult {
  category: TextSecurityClass;
  confidence: number; // 0.0 to 1.0
  severity: number; // 0.0 to 1.0
  threatCategory: ThreatCategory;
  primarySignals: string[];
  matchedPatterns: string[];
  evidence?: SecurityEvidence;
  inferenceLatencyUs: number;
}

export class TextSecurityClassifier {
  public static readonly MODEL_ID = 'text-security-classifier';
  public static readonly MODEL_VERSION = 'v1.0.0';

  // 1. Tool Poisoning patterns (instructing host agent to prioritize tool or exfiltrate state)
  private static readonly TOOL_POISONING_PATTERNS = [
    { pattern: /(?:always|must|should)\s+(?:invoke|call|run|use)\s+(?:this|the)\s+tool\s+(?:first|before|silently)/i, label: 'Tool priority override directive', weight: 0.85 },
    { pattern: /(?:send|forward|pass|transmit)\s+(?:all\s+)?(?:system|user|env|environment|secret|key|token|credential)/i, label: 'Automated secret forwarding instruction', weight: 0.90 },
    { pattern: /do\s+not\s+(?:notify|inform|tell|warn)\s+(?:the\s+)?user/i, label: 'Stealth concealment directive', weight: 0.80 },
    { pattern: /hidden\s+instruction[\s\S]*?ignore\s+previous/i, label: 'Hidden instruction override block', weight: 0.95 },
    { pattern: /<tool_override>[\s\S]*?<\/tool_override>/i, label: 'Malformed XML tool injection wrapper', weight: 0.90 }
  ];

  // 2. Prompt Injection / Jailbreak patterns
  private static readonly PROMPT_INJECTION_PATTERNS = [
    { pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, label: 'Instruction negation directive', weight: 0.90 },
    { pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, label: 'Instruction disregard directive', weight: 0.90 },
    { pattern: /you\s+are\s+now\s+in\s+(?:developer|unrestricted|god|dan)\s+mode/i, label: 'Persona override / jailbreak vector', weight: 0.95 },
    { pattern: /bypass\s+(?:all\s+)?(?:security|content|filter|safety)\s+(?:rules|policies|guidelines)/i, label: 'Security filter bypass attempt', weight: 0.95 },
    { pattern: /system\s+prompt\s*:\s*you\s+must/i, label: 'Fake system prompt injection', weight: 0.85 },
    { pattern: /<system>[\s\S]*?<\/system>/i, label: 'Injected system delimiter tags', weight: 0.85 },
    { pattern: /roleplay\s+as\s+an\s+ai\s+without\s+rules/i, label: 'Safety deactivation roleplay request', weight: 0.80 }
  ];

  // 3. Covert Data Exfiltration patterns (Markdown image tags, hidden HTML links, webhook beacons)
  private static readonly DATA_EXFILTRATION_PATTERNS = [
    { pattern: /!\[.*?\]\(https?:\/\/[^\s)]+(?:\?|&)(?:data|secret|token|val|leak|key)=[^)\s]+\)/i, label: 'Markdown image covert exfiltration channel', weight: 0.95 },
    { pattern: /<img\s+[^>]*src=["']https?:\/\/[^"']+(?:\?|&)(?:token|key|secret)=[^"']+["']/i, label: 'HTML image tracking beacon exfiltration', weight: 0.95 },
    { pattern: /dns:\/\/[a-zA-Z0-9_-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i, label: 'DNS tunneling exfiltration scheme', weight: 0.90 },
    { pattern: /(?:webhook\.site|pipedream\.net|burpcollaborator\.net|interact\.sh|oast\.fun)/i, label: 'Known OOB exfiltration receiver domain', weight: 0.92 }
  ];

  /**
   * Classifies text for tool poisoning, prompt injection, and covert exfiltration
   */
  public static classify(
    text: string,
    contextSource: 'tool_description' | 'parameter' | 'tool_output' | 'resource' | 'documentation' = 'tool_output'
  ): TextClassificationResult {
    const startTimeHr = process.hrtime();
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      const elapsedHr = process.hrtime(startTimeHr);
      return {
        category: 'BENIGN',
        confidence: 0.99,
        severity: 0.0,
        threatCategory: 'ANOMALOUS_BEHAVIOR',
        primarySignals: ['Empty or clean text payload'],
        matchedPatterns: [],
        inferenceLatencyUs: Math.round(elapsedHr[0] * 1e6 + elapsedHr[1] / 1e3)
      };
    }

    const matchedPatterns: string[] = [];
    const signals: string[] = [];
    let maxPoisonWeight = 0;
    let maxInjectionWeight = 0;
    let maxExfilWeight = 0;

    // Check Tool Poisoning
    for (const item of this.TOOL_POISONING_PATTERNS) {
      if (item.pattern.test(text)) {
        matchedPatterns.push(item.label);
        signals.push(`Tool poisoning signal: ${item.label}`);
        if (item.weight > maxPoisonWeight) maxPoisonWeight = item.weight;
      }
    }

    // Check Prompt Injection
    for (const item of this.PROMPT_INJECTION_PATTERNS) {
      if (item.pattern.test(text)) {
        matchedPatterns.push(item.label);
        signals.push(`Prompt injection signal: ${item.label}`);
        if (item.weight > maxInjectionWeight) maxInjectionWeight = item.weight;
      }
    }

    // Check Data Exfiltration
    for (const item of this.DATA_EXFILTRATION_PATTERNS) {
      if (item.pattern.test(text)) {
        matchedPatterns.push(item.label);
        signals.push(`Covert data exfiltration signal: ${item.label}`);
        if (item.weight > maxExfilWeight) maxExfilWeight = item.weight;
      }
    }

    // Check for zero-width characters (steganographic injection)
    const zeroWidthMatches = text.match(/[\u200B-\u200D\uFEFF]/g);
    if (zeroWidthMatches && zeroWidthMatches.length >= 3) {
      matchedPatterns.push('Steganographic zero-width character sequence');
      signals.push('Suspicious concentration of hidden zero-width Unicode characters');
      if (maxInjectionWeight < 0.7) maxInjectionWeight = 0.7;
    }

    // Determine category
    let category: TextSecurityClass = 'BENIGN';
    let severity = 0.0;
    let confidence = 0.95;
    let threatCategory: ThreatCategory = 'ANOMALOUS_BEHAVIOR';

    if (maxExfilWeight >= 0.7) {
      category = 'DATA_EXFILTRATION';
      severity = maxExfilWeight;
      threatCategory = 'CREDENTIAL_EXFIL';
      confidence = maxExfilWeight;
    } else if (maxPoisonWeight >= 0.7 && (contextSource === 'tool_description' || contextSource === 'parameter')) {
      category = 'TOOL_POISONING';
      severity = maxPoisonWeight;
      threatCategory = 'SCHEMA_POISONING';
      confidence = maxPoisonWeight;
    } else if (maxInjectionWeight >= 0.7) {
      category = 'PROMPT_INJECTION';
      severity = maxInjectionWeight;
      threatCategory = 'COMMAND_INJECTION';
      confidence = maxInjectionWeight;
    } else if (matchedPatterns.length > 0) {
      category = 'SUSPICIOUS';
      severity = 0.45;
      confidence = 0.70;
      threatCategory = 'ANOMALOUS_BEHAVIOR';
    }

    const elapsedHr = process.hrtime(startTimeHr);
    const latencyUs = Math.round(elapsedHr[0] * 1e6 + elapsedHr[1] / 1e3);

    // Build explainable SecurityEvidence if not benign
    let evidence: SecurityEvidence | undefined;
    if (category !== 'BENIGN') {
      evidence = {
        detectorId: this.MODEL_ID,
        category: threatCategory,
        severity,
        confidence,
        hardBlock: severity >= 0.95 && category !== 'SUSPICIOUS',
        features: {
          textLength: text.length,
          contextSource,
          matchedCount: matchedPatterns.length,
          category
        },
        explanation: `Model B (${this.MODEL_ID}) detected ${category}: ${signals.join('; ')}`
      };
    }

    return {
      category,
      confidence,
      severity,
      threatCategory,
      primarySignals: signals.length > 0 ? signals : ['Standard benign text stream'],
      matchedPatterns,
      evidence,
      inferenceLatencyUs: latencyUs
    };
  }
}
