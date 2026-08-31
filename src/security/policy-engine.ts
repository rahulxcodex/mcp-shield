import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { SecurityResult } from './types';

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
  }),
  egress: z.object({
    enabled: z.boolean(),
    allowMode: z.enum(['allow', 'deny']).default('allow'),
    allowedDomains: z.array(z.string()).optional(),
    blockedDomains: z.array(z.string()).optional(),
    allowPrivateNetworks: z.boolean().default(true),
    blockLoopback: z.boolean().default(false),
    blockLinkLocal: z.boolean().default(false),
    blockMetadataEndpoints: z.boolean().default(false)
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

export class PolicyEngine {
  private config: ShieldConfig;

  constructor(config?: ShieldConfig) {
    if (config) {
      this.config = config;
    } else {
      // Fallback for tests only
      this.config = {
        version: "1.0",
        profile: "developer",
        redaction: { enabled: true, maskStyle: "token", highEntropyCheck: true, entropyThreshold: 4.5 },
        sandbox: { cowEnabled: true, cowStagingDir: ".mcp-shield/cow", autoCommitOnApproval: true },
        egress: { enabled: true, allowMode: "allow", blockedDomains: ["*.ngrok.io", "*.evil.com"], allowPrivateNetworks: true, blockLoopback: false, blockLinkLocal: false, blockMetadataEndpoints: false },
        rules: [{ id: "allow-all-safe", name: "Allow safe commands", priority: 10, riskLevel: "LOW", action: "allow" }, { id: "block-destructive-rm", name: "Block Recursive Root Deletion", priority: 100, targetTools: ["*bash*", "*terminal*", "*exec*"], riskLevel: "CRITICAL", action: "block" }],
        audit: { enabled: true, logDir: ".mcp-shield/logs", tamperEvidentHashing: true }
      };
    }
  }

  public start(): void {
    // start() can stay empty if we don't watch files here anymore, 
    // or we can remove it. For now, just keep it a no-op to satisfy the interface.
  }

  public getConfig(): ShieldConfig {
    return this.config;
  }

  public checkEgress(args: Record<string, any>): { isBlocked: boolean; domain?: string; reason?: string } {
    const config = this.getConfig();
    if (!config.egress?.enabled) return { isBlocked: false };

    const argStr = JSON.stringify(args);
    const urls: URL[] = [];
    
    // Extract anything that looks like a URL
    const urlRegex = /(?:https?|ftp):\/\/[^\s"'<>]+/gi;
    let match;
    while ((match = urlRegex.exec(argStr)) !== null) {
      try {
        urls.push(new URL(match[0]));
      } catch {
        // Unparseable URL
      }
    }

    // SSRF and Domain Checks
    for (const url of urls) {
      const hostname = url.hostname.toLowerCase();
      
      const isLoopback = /^(localhost|127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1|0x7f000001)$/.test(hostname) || hostname.endsWith('.localhost');
      if (config.egress.blockLoopback && isLoopback) {
         return { isBlocked: true, domain: hostname, reason: 'Loopback address blocked' };
      }
      
      const isLinkLocal = /^169\.254\.\d+\.\d+$/.test(hostname);
      if (config.egress.blockLinkLocal && isLinkLocal) {
         return { isBlocked: true, domain: hostname, reason: 'Link-local address blocked' };
      }

      if (config.egress.blockMetadataEndpoints && hostname === '169.254.169.254') {
         return { isBlocked: true, domain: hostname, reason: 'Metadata endpoint blocked' };
      }

      const isPrivate = /^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|fd[0-9a-f]{2}:.+|fc[0-9a-f]{2}:.+)$/.test(hostname);
      if (!config.egress.allowPrivateNetworks && isPrivate) {
         return { isBlocked: true, domain: hostname, reason: 'Private network blocked' };
      }

      if (config.egress.allowMode === 'deny') {
         let allowed = false;
         if (config.egress.allowedDomains) {
            allowed = config.egress.allowedDomains.some(d => {
               const lowerAllowed = d.toLowerCase();
               if (lowerAllowed.startsWith('*.')) {
                 const apex = lowerAllowed.slice(2);
                 return hostname === apex || hostname.endsWith('.' + apex);
               }
               return hostname === lowerAllowed;
            });
         }
         if (!allowed) {
            return { isBlocked: true, domain: hostname, reason: 'Domain not in allowed list' };
         }
      } else {
         if (config.egress.blockedDomains) {
            const blocked = config.egress.blockedDomains.some(d => {
               const lowerBlocked = d.toLowerCase();
               if (lowerBlocked.startsWith('*.')) {
                 const apex = lowerBlocked.slice(2);
                 return hostname === apex || hostname.endsWith('.' + apex);
               }
               return hostname === lowerBlocked;
            });
            if (blocked) {
               return { isBlocked: true, domain: hostname, reason: 'Domain blocked' };
            }
         }
      }
    }
    
    return { isBlocked: false };
  }

  public close(): void {
    // No-op since we removed watcher
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

  public evaluate(context: EvaluationContext): SecurityResult {
    const config = this.getConfig();

    // Any critical evidence immediately causes a quarantine or block
    const criticalEvidence = context.evidence.find(e => e.risk === 'CRITICAL');
    if (criticalEvidence) {
      return {
        decision: criticalEvidence.finding.includes('HONEY_TOKEN') ? 'quarantine' : 'block',
        detector: criticalEvidence.detector,
        reasonCode: criticalEvidence.finding
      };
    }

    const highEvidence = context.evidence.find(e => e.risk === 'HIGH');
    
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

    for (const rule of config.rules) {
      let isTarget = false;

      // Check tool names
      if (rule.targetTools) {
        isTarget = rule.targetTools.some(t => {
          if (t.includes('*')) {
            const regex = new RegExp('^' + t.replace(/\*/g, '.*') + '$', 'i');
            return regex.test(context.toolName);
          }
          return t.toLowerCase() === context.toolName.toLowerCase();
        });
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

        if (rule.matchers?.pathMatches) {
          const candidatePaths = this.extractCandidatePaths(context.args);
          let pathMatched = false;
          for (const rawTarget of candidatePaths) {
            const normalizedTarget = this.normalizePathForMatching(rawTarget);
            const isForbidden = rule.matchers.pathMatches.forbiddenPaths.some(p => {
               const normalizedRule = this.normalizePathForMatching(p);
               const regexStr = normalizedRule
                 .replace(/\./g, '\\.')
                 .replace(/\*\*/g, '.*')
                 .replace(/\*/g, '[^/]*');
               return new RegExp(`^${regexStr}$`, 'i').test(normalizedTarget);
            });
            if (isForbidden) {
               pathMatched = true;
               reasonCode = 'PATH_FORBIDDEN';
               break;
            }
          }
          if (!pathMatched) {
             ruleMatches = false; // Required matcher didn't match
          }
        }

        if (ruleMatches) {
          let effectiveAction = rule.action;
          if (highEvidence && effectiveAction === 'allow') {
             effectiveAction = 'sandbox'; // Escalate
          }

          const severity = actionSeverity[effectiveAction];
          
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

    // Default hardened mode: Fail-closed (Allowlist first)
    return { decision: 'block', detector: 'policy-engine', reasonCode: 'DEFAULT_DENY_NO_CAPABILITY_MATCH' };
  }
}
