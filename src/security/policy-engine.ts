import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { SecurityResult } from './types';

export const PolicyRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  targetTools: z.array(z.string()),
  riskLevel: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  action: z.enum(['block', 'prompt', 'sandbox', 'allow']),
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
    blockedDomains: z.array(z.string()),
  }),
  rules: z.array(PolicyRuleSchema),
  audit: z.object({
    enabled: z.boolean(),
    logDir: z.string(),
    tamperProofHashing: z.boolean(),
  }),
});
export type ShieldConfig = z.infer<typeof ShieldConfigSchema>;

export class PolicyEngine {
  private config: ShieldConfig | null = null;
  private watcher: fs.FSWatcher | null = null;

  constructor(private configPath: string = 'shield.config.default.yaml') {
    this.setupWatcher();
  }

  private setupWatcher() {
    if (fs.existsSync(this.configPath)) {
      this.watcher = fs.watch(this.configPath, (eventType) => {
        if (eventType === 'change') {
           try {
              this.loadConfig();
              console.error(`[MCP-SHIELD] Policy config hot-reloaded.`);
           } catch(e) {
              // ignore parse errors on hot reload
           }
        }
      });
      if (this.watcher && typeof (this.watcher as any).unref === 'function') {
        (this.watcher as any).unref();
      }
    }
  }

  public loadConfig(): void {
    if (fs.existsSync(this.configPath)) {
      const fileContents = fs.readFileSync(this.configPath, 'utf8');
      const parsedYaml = yaml.load(fileContents);
      this.config = ShieldConfigSchema.parse(parsedYaml);
    } else {
      throw new Error(`Config file not found: ${this.configPath}`);
    }
  }

  public getConfig(): ShieldConfig {
    if (!this.config) {
      try {
        this.loadConfig();
      } catch (err) {
        // Fallback config for development/testing if no config file exists
        // but it must pass validation
        if (err instanceof Error && err.message.includes('Config file not found')) {
          const defaultConfig = {
            version: "1.0",
            profile: "developer",
            redaction: { enabled: true, maskStyle: "token", highEntropyCheck: true, entropyThreshold: 4.5 },
            sandbox: { cowEnabled: true, cowStagingDir: ".mcp-shield/cow", autoCommitOnApproval: true },
            egress: { enabled: true, blockedDomains: ["*.ngrok.io", "*.evil.com"] },
            rules: [{ id: "block-destructive-rm", name: "Block Recursive Root Deletion", targetTools: ["*bash*", "*terminal*", "*exec*"], riskLevel: "CRITICAL", action: "block" }],
            audit: { enabled: true, logDir: ".mcp-shield/logs", tamperProofHashing: true }
          };
          this.config = ShieldConfigSchema.parse(defaultConfig);
        } else {
          throw err;
        }
      }
    }
    return this.config!;
  }

  public checkEgress(args: Record<string, any>): { isBlocked: boolean; domain?: string } {
    const config = this.getConfig();
    if (!config.egress?.enabled || !config.egress.blockedDomains) return { isBlocked: false };

    const argStr = JSON.stringify(args);
    
    // 1. Check for standard domain names and hostnames
    const urlRegex = /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
    let match;
    while ((match = urlRegex.exec(argStr)) !== null) {
      const domain = match[1].toLowerCase();
      const isBlocked = config.egress.blockedDomains.some(blocked => {
        const lowerBlocked = blocked.toLowerCase();
        if (lowerBlocked.startsWith('*.')) {
          const apex = lowerBlocked.slice(2);
          if (domain === apex || domain.endsWith('.' + apex)) {
            return true;
          }
        }
        const regexStr = lowerBlocked.replace(/\./g, '\\.').replace(/\*/g, '.*');
        return new RegExp(`^${regexStr}$`, 'i').test(domain);
      });
      
      if (isBlocked) return { isBlocked: true, domain };
    }

    // 2. Check for raw IP literals, Hex-encoded IPs, and Dword IPs targeted at egress exfiltration
    const ipPatterns = [
      /(?:https?:\/\/)?((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?/g,
      /(?:https?:\/\/)?(0x[0-9a-fA-F]{8})/g,
      /(?:https?:\/\/)?(\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\])(?::\d+)?/g
    ];

    for (const ipRegex of ipPatterns) {
      let ipMatch;
      while ((ipMatch = ipRegex.exec(argStr)) !== null) {
        const targetIp = ipMatch[1];
        // If blacklisted specifically or if blocked domain matches
        const isBlocked = config.egress.blockedDomains.some(blocked => {
          return blocked === targetIp || blocked === '*' || blocked === '0.0.0.0/0';
        });
        if (isBlocked) return { isBlocked: true, domain: targetIp };
      }
    }
    
    return { isBlocked: false };
  }

  public close(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
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
          ['path', 'file', 'filename', 'filepath', 'target', 'source', 'dest', 'destination', 'uri', 'dir', 'directory', 'cwd'].includes(lowerKey) ||
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

  public evaluateToolCall(toolName: string, args: Record<string, any>): SecurityResult {
    const config = this.getConfig();

    for (const rule of config.rules) {
      const isTarget = rule.targetTools.some(t => {
        if (t.includes('*')) {
          const regex = new RegExp('^' + t.replace(/\*/g, '.*') + '$', 'i');
          return regex.test(toolName);
        }
        return t.toLowerCase() === toolName.toLowerCase();
      });

      if (!isTarget) continue;

      if (rule.matchers) {
        if (rule.matchers.pathMatches) {
          const candidatePaths = this.extractCandidatePaths(args);
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
            if (isForbidden) return { decision: rule.action as any, detector: 'policy-engine', reasonCode: 'PATH_FORBIDDEN', ruleId: rule.id };
          }
        }
      } else {
         return { decision: rule.action as any, detector: 'policy-engine', reasonCode: 'RULE_MATCH', ruleId: rule.id };
      }
    }

    return { decision: 'allow', detector: 'policy-engine', reasonCode: 'DEFAULT_ALLOW' };
  }
}
