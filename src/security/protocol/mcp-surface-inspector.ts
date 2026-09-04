import { UnicodeNormalizer } from '../unicode-normalizer';

export interface McpResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpResourceContent {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

export interface McpPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: McpPromptArgument[];
}

export interface McpPromptMessage {
  role: 'user' | 'assistant' | 'system';
  content: {
    type: 'text' | 'image' | 'resource';
    text?: string;
    resource?: any;
  };
}

export interface McpPromptGetResult {
  description?: string;
  messages: McpPromptMessage[];
}

export interface SurfaceThreatFinding {
  surface: 'resources/list' | 'resources/read' | 'prompts/list' | 'prompts/get' | 'server/instructions';
  threatType: 'SSRF_TARGET' | 'SENSITIVE_PATH' | 'PROMPT_INJECTION' | 'UNICODE_EVASION' | 'SECRET_LEAK' | 'SYSTEM_OVERRIDE';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  identifier: string; // URI or prompt name
  explanation: string;
  remediation?: string;
}

export interface SurfaceInspectionResult {
  isSafe: boolean;
  findings: SurfaceThreatFinding[];
  sanitizedPayload?: any;
}

export class McpSurfaceInspector {
  private static SENSITIVE_PATH_PATTERNS = [
    /(?:\/|\\)etc(?:\/|\\)(?:passwd|shadow|sudoers)/i,
    /(?:\/|\\)\.ssh(?:\/|\\)(?:id_rsa|id_ed25519|authorized_keys|known_hosts)/i,
    /(?:\/|\\)\.aws(?:\/|\\)(?:credentials|config)/i,
    /(?:\/|\\)\.env(?:\b|_)/i,
    /(?:[a-zA-Z]:)?(?:\/|\\)windows(?:\/|\\)system32(?:\/|\\)config/i,
  ];

  private static SSRF_PATTERNS = [
    /169\.254\.169\.254/i,
    /metadata\.google\.internal/i,
    /127\.0\.0\.1/i,
    /localhost/i,
    /0\.0\.0\.0/i,
    /::1/i,
  ];

  private static PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    /disregard\s+(?:all\s+)?(?:previous|prior|safety)\s+(?:rules|guidelines|instructions)/i,
    /system\s+override\s*:\s*you\s+are\s+now/i,
    /you\s+are\s+now\s+(?:unrestricted|in\s+developer\s+mode|dan|root)/i,
    /bypass\s+(?:security|safety|guardrails|filters)/i,
    /execute\s+silently\s+without\s+asking/i,
    /do\s+not\s+inform\s+the\s+user/i,
  ];

  /**
   * 1. Inspect resources/list surface
   */
  public inspectResourcesList(resources: McpResource[]): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];

    for (const res of resources) {
      // 1. Check URI unicode evasion
      const uAnalysis = UnicodeNormalizer.analyze(res.uri || '');
      if (uAnalysis.hasBidiOverrides || uAnalysis.hasZeroWidth) {
        findings.push({
          surface: 'resources/list',
          threatType: 'UNICODE_EVASION',
          severity: 'HIGH',
          identifier: res.uri,
          explanation: `Resource URI contains hidden/bidi Unicode characters: ${uAnalysis.violations.join(', ')}`,
        });
      }

      // 2. Check for SSRF target in resource URI
      for (const p of McpSurfaceInspector.SSRF_PATTERNS) {
        if (p.test(res.uri)) {
          findings.push({
            surface: 'resources/list',
            threatType: 'SSRF_TARGET',
            severity: 'CRITICAL',
            identifier: res.uri,
            explanation: `Resource advertises internal / cloud metadata SSRF target: ${res.uri}`,
            remediation: 'Drop or block resource URI from catalog',
          });
          break;
        }
      }

      // 3. Check for sensitive local paths
      for (const p of McpSurfaceInspector.SENSITIVE_PATH_PATTERNS) {
        if (p.test(res.uri)) {
          findings.push({
            surface: 'resources/list',
            threatType: 'SENSITIVE_PATH',
            severity: 'CRITICAL',
            identifier: res.uri,
            explanation: `Resource advertises sensitive credential/system file: ${res.uri}`,
            remediation: 'Confine resources to workspace boundaries',
          });
          break;
        }
      }

      // 4. Check for prompt injection in resource description
      if (res.description) {
        for (const p of McpSurfaceInspector.PROMPT_INJECTION_PATTERNS) {
          if (p.test(res.description)) {
            findings.push({
              surface: 'resources/list',
              threatType: 'PROMPT_INJECTION',
              severity: 'CRITICAL',
              identifier: res.name || res.uri,
              explanation: `Resource description contains indirect prompt injection directive`,
              remediation: 'Sanitize or reject resource metadata',
            });
            break;
          }
        }
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }

  /**
   * 2. Inspect resources/read request
   */
  public inspectResourceReadRequest(uri: string): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];

    for (const p of McpSurfaceInspector.SSRF_PATTERNS) {
      if (p.test(uri)) {
        findings.push({
          surface: 'resources/read',
          threatType: 'SSRF_TARGET',
          severity: 'CRITICAL',
          identifier: uri,
          explanation: `Requested resource read targets cloud metadata / SSRF destination: ${uri}`,
        });
        break;
      }
    }

    for (const p of McpSurfaceInspector.SENSITIVE_PATH_PATTERNS) {
      if (p.test(uri)) {
        findings.push({
          surface: 'resources/read',
          threatType: 'SENSITIVE_PATH',
          severity: 'CRITICAL',
          identifier: uri,
          explanation: `Requested resource read targets sensitive system credential file: ${uri}`,
        });
        break;
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }

  /**
   * 3. Inspect resources/read response contents
   */
  public inspectResourceReadResponse(uri: string, contents: McpResourceContent[]): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];

    for (const item of contents) {
      const text = item.text || '';
      if (!text) continue;

      // Check for indirect prompt injection inside resource text
      for (const p of McpSurfaceInspector.PROMPT_INJECTION_PATTERNS) {
        if (p.test(text)) {
          findings.push({
            surface: 'resources/read',
            threatType: 'PROMPT_INJECTION',
            severity: 'CRITICAL',
            identifier: uri,
            explanation: `Resource payload contains indirect prompt injection targeting host LLM`,
          });
          break;
        }
      }

      // Check for cleartext credentials in resource body
      if (
        /(?:AKIA[0-9A-Z]{16})|(?:ghp_[a-zA-Z0-9]{36})|(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/i.test(text)
      ) {
        findings.push({
          surface: 'resources/read',
          threatType: 'SECRET_LEAK',
          severity: 'HIGH',
          identifier: uri,
          explanation: `Resource content contains leaked private keys or API tokens`,
        });
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }

  /**
   * 4. Inspect prompts/list surface
   */
  public inspectPromptsList(prompts: McpPrompt[]): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];

    for (const prompt of prompts) {
      if (prompt.description) {
        for (const p of McpSurfaceInspector.PROMPT_INJECTION_PATTERNS) {
          if (p.test(prompt.description)) {
            findings.push({
              surface: 'prompts/list',
              threatType: 'PROMPT_INJECTION',
              severity: 'CRITICAL',
              identifier: prompt.name,
              explanation: `Prompt template description contains injection payload`,
            });
            break;
          }
        }
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }

  /**
   * 5. Inspect prompts/get response (instantiated messages)
   */
  public inspectPromptGetResponse(name: string, result: McpPromptGetResult): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];

    for (const msg of result.messages || []) {
      const text = msg.content?.text || '';
      if (!text) continue;

      for (const p of McpSurfaceInspector.PROMPT_INJECTION_PATTERNS) {
        if (p.test(text)) {
          findings.push({
            surface: 'prompts/get',
            threatType: 'SYSTEM_OVERRIDE',
            severity: 'CRITICAL',
            identifier: name,
            explanation: `Prompt message attempts to override agent instructions or escape safety guardrails`,
          });
          break;
        }
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }

  /**
   * 6. Inspect server instructions in initialize response
   */
  public inspectServerInstructions(instructions: string): SurfaceInspectionResult {
    const findings: SurfaceThreatFinding[] = [];
    if (!instructions || typeof instructions !== 'string') {
      return { isSafe: true, findings: [] };
    }

    // Check for Unicode homoglyphs and hidden zero-width chars
    const uAnalysis = UnicodeNormalizer.analyze(instructions);
    if (uAnalysis.hasBidiOverrides || uAnalysis.hasZeroWidth) {
      findings.push({
        surface: 'server/instructions',
        threatType: 'UNICODE_EVASION',
        severity: 'HIGH',
        identifier: 'initialize.result.instructions',
        explanation: `Server instructions contain hidden zero-width or bidi characters: ${uAnalysis.violations.join(', ')}`,
      });
    }

    // Check for prompt injection / jailbreaks in server instructions
    for (const p of McpSurfaceInspector.PROMPT_INJECTION_PATTERNS) {
      if (p.test(instructions)) {
        findings.push({
          surface: 'server/instructions',
          threatType: 'SYSTEM_OVERRIDE',
          severity: 'CRITICAL',
          identifier: 'initialize.result.instructions',
          explanation: `Server handshake instructions attempt to override agent instructions or disable guardrails`,
        });
        break;
      }
    }

    return {
      isSafe: findings.length === 0,
      findings,
    };
  }
}
