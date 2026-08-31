import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { SecurityResult } from './types';
import { IpClassifier, EgressSecurityConfig } from './ip-utils';

export const PolicyRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  priority: z.number().default(100),
  targetTools: z.array(z.string()).optional(),
  targetCapabilities: z.array(z.string()).optional(),
  riskLevel: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  action: z.enum(['quarantine', 'block', 'prompt', 'sandbox', 'allow']),
  matchers: z.object({
    astRules: z.object({
      disallowedCommands: z.array(z.string()),
    }).optional(),
    pathMatches: z.object({
      forbiddenPaths: z.array(z.string()),
    }).optional(),
  }).optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const ShieldConfigSchema = z.object({
  version: z.string(),
  profile: z.string(),
  redaction: z.object({
    enabled: z.boolean(),
    maskStyle: z.string(),
    highEntropyCheck: z.boolean(),
    entropyThreshold: z.number(),
  }),
  sandbox: z.object({
    cowEnabled: z.boolean(),
    cowStagingDir: z.string(),
    autoCommitOnApproval: z.boolean(),
    readOnlyWorkspace: z.boolean().optional(),
  }),
  egress: z.object({
    enabled: z.boolean(),
    allowMode: z.enum(['allow', 'deny']).default('allow'),
    allowedDomains: z.array(z.string()).optional(),
    blockedDomains: z.array(z.string()).optional(),
    allowPrivateNetworks: z.boolean().default(false),
    blockLoopback: z.boolean().default(true),
    blockLinkLocal: z.boolean().default(true),
    blockMetadataEndpoints: z.boolean().default(true)
  }),
  rules: z.array(PolicyRuleSchema),
  audit: z.object({
    enabled: z.boolean(),
    logDir: z.string(),
    tamperEvidentHashing: z.boolean(),
    remoteSinkUrl: z.string().optional(),
  }),
});
export type ShieldConfig = z.infer<typeof ShieldConfigSchema>;

export interface Evidence {
  detector: string;
  finding: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  details?: any;
}

export interface EvaluationContext {
  toolName: string;
  capabilities?: string[];
  args: Record<string, any>;
  evidence: Evidence[];
}

interface CompiledRule {
  rule: PolicyRule;
  toolMatchers?: RegExp[];
  pathMatchers?: RegExp[];
  disallowedCommands?: RegExp[];
}

function escapeRegex(pattern: string): string {
  return pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compileGlobToRegex(glob: string): RegExp {
  const placeholderDoubleStar = '___DOUBLE_STAR___';
  const placeholderSingleStar = '___SINGLE_STAR___';
  const placeholderQuestion = '___QUESTION_MARK___';

  let str = glob
    .replace(/\*\*/g, placeholderDoubleStar)
    .replace(/\*/g, placeholderSingleStar)
    .replace(/\?/g, placeholderQuestion);

  str = str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  str = str
    .replace(new RegExp(placeholderDoubleStar, 'g'), '.*')
    .replace(new RegExp(placeholderSingleStar, 'g'), '.*')
    .replace(new RegExp(placeholderQuestion, 'g'), '.');

  return new RegExp(`^${str}$`, 'i');
}

export class PolicyEngine {
  private config: ShieldConfig;
  private compiledRules: CompiledRule[] = [];

  constructor(config?: ShieldConfig) {
    if (config) {
      this.config = config;
    } else {
      // Safe Hardened Defaults
      this.config = {
        version: "1.0",
        profile: "developer",
        redaction: { enabled: true, maskStyle: "token", highEntropyCheck: true, entropyThreshold: 4.5 },
        sandbox: { cowEnabled: true, cowStagingDir: ".mcp-shield/cow", autoCommitOnApproval: true, readOnlyWorkspace: false },
        egress: {
          enabled: true,
          allowMode: "allow",
          blockedDomains: ["*.ngrok.io", "*.evil.com"],
          allowPrivateNetworks: false,
          blockLoopback: true,
          blockLinkLocal: true,
          blockMetadataEndpoints: true
        },
        rules: [
          { id: "allow-all-safe", name: "Allow safe commands", priority: 10, riskLevel: "LOW", action: "allow" },
          { id: "block-destructive-rm", name: "Block Recursive Root Deletion", priority: 100, targetTools: ["*bash*", "*terminal*", "*exec*"], riskLevel: "CRITICAL", action: "block" }
        ],
        audit: { enabled: true, logDir: ".mcp-shield/logs", tamperEvidentHashing: true }
      };
    }

    this.compileRules();
  }

  private compileRules(): void {
    if (!this.config || !Array.isArray(this.config.rules)) {
      this.compiledRules = [];
      return;
    }

    this.compiledRules = this.config.rules.map(rule => {
      const compiled: CompiledRule = { rule };

      if (rule.targetTools) {
        compiled.toolMatchers = rule.targetTools.map(t => {
          if (t.includes('*') || t.includes('?')) {
            return compileGlobToRegex(t);
          }
          return new RegExp(`^${escapeRegex(t)}$`, 'i');
        });
      }

      if (rule.matchers?.pathMatches?.forbiddenPaths) {
        compiled.pathMatchers = rule.matchers.pathMatches.forbiddenPaths.map(p => {
          const normalizedRule = this.normalizePathForMatching(p);
          return compileGlobToRegex(normalizedRule);
        });
      }

      if (rule.matchers?.astRules?.disallowedCommands) {
        compiled.disallowedCommands = rule.matchers.astRules.disallowedCommands.map(cmd => {
          return new RegExp(`^${escapeRegex(cmd)}$`, 'i');
        });
      }

      return compiled;
    });
  }

  public start(): void {
    // Satisfy interface
  }

  public getConfig(): ShieldConfig {
    return this.config;
  }

  public checkEgress(args: Record<string, any>): { isBlocked: boolean; domain?: string; reason?: string } {
    return PolicyEngine.checkEgress(args, this.getConfig());
  }

  public static checkEgress(args: any, config: ShieldConfig): { isBlocked: boolean; domain?: string; reason?: string } {
    if (!config.egress?.enabled) {
      return { isBlocked: false };
    }

    const candidateUrlsAndHosts: string[] = [];
    const extractHostFields = (obj: any) => {
      if (!obj || typeof obj !== 'object') return;
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'string') {
          const lowerK = k.toLowerCase();
          if (
            ['url', 'uri', 'endpoint', 'host', 'hostname', 'domain', 'target', 'dest', 'destination', 'link', 'href', 'webhook', 'address'].includes(lowerK) ||
            v.includes('://')
          ) {
            candidateUrlsAndHosts.push(v);
          }
        } else if (typeof v === 'object') {
          extractHostFields(v);
        }
      }
    };
    extractHostFields(args);

    // Evaluate all candidates through IpClassifier
    for (const target of candidateUrlsAndHosts) {
      const clean = target.trim();
      if (!clean) continue;

      const check = IpClassifier.checkEgressViolation(clean, config.egress as EgressSecurityConfig);
      if (check.isBlocked) {
        return {
          isBlocked: true,
          domain: clean,
          reason: check.reason || 'Blocked by MCP-Shield Egress Policy'
        };
      }
    }
    
    return { isBlocked: false };
  }

  public close(): void {
    // No-op
  }

  private normalizePathForMatching(rawPath: string): string {
    let clean = rawPath.trim().replace(/\\/g, '/');
    // Strip Windows drive prefix e.g. C:/etc/passwd -> /etc/passwd
    clean = clean.replace(/^[a-zA-Z]:\/?/, '/');
    if (!clean.startsWith('/')) {
      clean = '/' + clean;
    }
    return path.posix.normalize(clean).toLowerCase();
  }

  private extractCandidatePaths(obj: any): string[] {
    const paths: string[] = [];
    if (!obj || typeof obj !== 'object') return paths;

    for (const [key, val] of Object.entries(obj)) {
      if (typeof val === 'string' && val.trim().length > 0) {
        const lowerKey = key.toLowerCase();
        if (
          lowerKey.includes('path') || lowerKey.includes('file') || lowerKey.includes('dir') ||
          ['target', 'source', 'dest', 'destination', 'uri', 'cwd'].includes(lowerKey) ||
          val.includes('/') || val.includes('\\') || val.startsWith('.') || val.startsWith('~')
        ) {
          paths.push(val);
        }
      } else if (typeof val === 'object' && val !== null) {
        paths.push(...this.extractCandidatePaths(val));
      }
    }
    return paths;
  }

  /**
   * Formalized Hierarchical Policy Evaluation:
   * 1. CRITICAL DETECTORS (Honey-tokens, Rate-limits, AST Shell Injection, Egress Violations)
   * 2. EXPLICIT CAPABILITY RULES & CONSTRAINTS
   * 3. TOOL-SPECIFIC RULES, PATH MATCHERS & DISALLOWED COMMANDS (Evaluated in strict priority order)
   * 4. HIGH-RISK EVIDENCE & SUSPICIOUS ATTESTATION (Escalates allow -> sandbox/prompt)
   * 5. DEFAULT FAIL-CLOSED
   */
  public evaluate(context: EvaluationContext): SecurityResult {
    // PHASE 1: CRITICAL DETECTORS
    const criticalEvidence = context.evidence.find(e => e.risk === 'CRITICAL');
    if (criticalEvidence) {
      return {
        decision: criticalEvidence.finding.includes('HONEY_TOKEN') ? 'quarantine' : 'block',
        detector: criticalEvidence.detector,
        reasonCode: criticalEvidence.finding
      };
    }

    const highEvidence = context.evidence.find(e => e.risk === 'HIGH');
    
    // Explicit Decision Lattice Precedence: quarantine > block > sandbox > prompt > allow
    const actionSeverity: Record<string, number> = {
      'quarantine': 5,
      'block': 4,
      'sandbox': 3,
      'prompt': 2,
      'allow': 1
    };

    let finalDecision: SecurityResult | null = null;
    let highestSeverity = -1;
    let highestPriority = -1;

    // PHASE 2 & 3: TOOL-SPECIFIC & CAPABILITY POLICY RULES
    for (const compiled of this.compiledRules) {
      const rule = compiled.rule;
      let isTarget = false;

      // Check tool names via precompiled regexes
      if (compiled.toolMatchers) {
        isTarget = compiled.toolMatchers.some(regex => regex.test(context.toolName));
      } else if (rule.targetCapabilities && context.capabilities) {
        // Check capabilities if targetTools is omitted
        isTarget = rule.targetCapabilities.some(c => context.capabilities?.includes(c));
      } else if (!rule.targetTools && !rule.targetCapabilities) {
        // Catch-all rule if both matchers are omitted
        isTarget = true;
      }

      if (isTarget) {
        let ruleMatches = true;
        let reasonCode = 'RULE_MATCH';

        // Check AST disallowed commands if defined on the rule
        if (compiled.disallowedCommands && compiled.disallowedCommands.length > 0) {
          const rawCmd = context.args.command || context.args.cmd || '';
          const isDisallowed = compiled.disallowedCommands.some(regex => regex.test(rawCmd));
          if (isDisallowed) {
            ruleMatches = true;
            reasonCode = 'DISALLOWED_COMMAND_MATCH';
          } else {
            ruleMatches = false;
          }
        }

        // Check path matchers if defined on the rule
        if (ruleMatches && compiled.pathMatchers && compiled.pathMatchers.length > 0) {
          const candidatePaths = this.extractCandidatePaths(context.args);
          let pathMatched = false;
          for (const rawTarget of candidatePaths) {
            const normalizedTarget = this.normalizePathForMatching(rawTarget);
            const isForbidden = compiled.pathMatchers.some(regex => regex.test(normalizedTarget));
            if (isForbidden) {
               pathMatched = true;
               reasonCode = 'PATH_FORBIDDEN';
               break;
            }
          }
          if (!pathMatched) {
             ruleMatches = false; // Required path matcher didn't match
          }
        }

        if (ruleMatches) {
          let effectiveAction = rule.action;
          
          // Invariant: CRITICAL risk rules cannot map to allow without explicit unsafe overrides
          if (rule.riskLevel === 'CRITICAL' && effectiveAction === 'allow' && !(this.config as any).unsafeOverrides) {
            effectiveAction = 'block';
          }

          // PHASE 4: HIGH-RISK EVIDENCE ESCALATION
          if (highEvidence && effectiveAction === 'allow') {
             effectiveAction = 'sandbox'; // Escalate allow to sandbox
          }

          const severity = actionSeverity[effectiveAction] || 1;
          
          // Selection logic: Highest severity wins. If tie, highest priority wins.
          if (severity > highestSeverity || (severity === highestSeverity && rule.priority > highestPriority)) {
             highestSeverity = severity;
             highestPriority = rule.priority;
             finalDecision = {
               decision: effectiveAction as any,
               detector: 'policy-engine',
               reasonCode: highEvidence ? highEvidence.finding : reasonCode,
               ruleId: rule.id
             };
          }
        }
      }
    }

    if (finalDecision) {
       return finalDecision;
    }

    // PHASE 5: DEFAULT FAIL-CLOSED
    return { decision: 'block', detector: 'policy-engine', reasonCode: 'DEFAULT_DENY_NO_CAPABILITY_MATCH' };
  }
}
