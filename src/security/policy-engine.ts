import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface PolicyRule {
  id: string;
  name: string;
  targetTools: string[];
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: 'block' | 'prompt' | 'sandbox' | 'allow';
  matchers?: {
    astRules?: {
      disallowedCommands: string[];
    };
    pathMatches?: {
      forbiddenPaths: string[];
    };
  };
}

export interface ShieldConfig {
  version: string;
  profile: string;
  redaction: {
    enabled: boolean;
    maskStyle: string;
    highEntropyCheck: boolean;
    entropyThreshold: number;
  };
  sandbox: {
    cowEnabled: boolean;
    cowStagingDir: string;
    autoCommitOnApproval: boolean;
  };
  egress: {
    enabled: boolean;
    blockedDomains: string[];
  };
  rules: PolicyRule[];
  audit: {
    enabled: boolean;
    logDir: string;
    tamperProofHashing: boolean;
  };
}

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
    }
  }

  public loadConfig(): void {
    if (fs.existsSync(this.configPath)) {
      const fileContents = fs.readFileSync(this.configPath, 'utf8');
      this.config = yaml.load(fileContents) as ShieldConfig;
    } else {
      throw new Error(`Config file not found: ${this.configPath}`);
    }
  }

  public getConfig(): ShieldConfig {
    if (!this.config) {
      try {
        this.loadConfig();
      } catch {
        this.config = {
          version: "1.0",
          profile: "developer",
          redaction: {
            enabled: true,
            maskStyle: "token",
            highEntropyCheck: true,
            entropyThreshold: 4.5
          },
          sandbox: {
            cowEnabled: true,
            cowStagingDir: ".mcp-shield/cow",
            autoCommitOnApproval: true
          },
          egress: {
            enabled: true,
            blockedDomains: ["*.ngrok.io", "*.evil.com"]
          },
          rules: [
            {
              id: "block-destructive-rm",
              name: "Block Recursive Root Deletion",
              targetTools: ["*bash*", "*terminal*", "*exec*"],
              riskLevel: "CRITICAL",
              action: "block"
            }
          ],
          audit: {
            enabled: true,
            logDir: ".mcp-shield/logs",
            tamperProofHashing: true
          }
        };
      }
    }
    return this.config!;
  }

  public checkEgress(args: Record<string, any>): { isBlocked: boolean; domain?: string } {
    const config = this.getConfig();
    if (!config.egress?.enabled || !config.egress.blockedDomains) return { isBlocked: false };

    const argStr = JSON.stringify(args);
    // Note: This is a naive regex extractor and can be fooled by encoding tricks (ev%69l.com), 
    // IP literals, and punycode. It is a defense-in-depth measure, not a full network sandbox.
    const urlRegex = /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
    
    let match;
    while ((match = urlRegex.exec(argStr)) !== null) {
      const domain = match[1];
      const isBlocked = config.egress.blockedDomains.some(blocked => {
        const regexStr = blocked.replace(/\./g, '\\.').replace(/\*/g, '.*');
        return new RegExp(`^${regexStr}$`).test(domain);
      });
      
      if (isBlocked) return { isBlocked: true, domain };
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
    if (!clean.startsWith('/')) {
      clean = '/' + clean;
    }
    return path.posix.normalize(clean).toLowerCase();
  }

  public evaluateToolCall(toolName: string, args: Record<string, any>): { action: PolicyRule['action']; rule?: PolicyRule } {
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
        if (rule.matchers.pathMatches && (args.path || args.file || args.filename)) {
          const rawTarget = (args.path || args.file || args.filename) as string;
          const normalizedTarget = this.normalizePathForMatching(rawTarget);

          const isForbidden = rule.matchers.pathMatches.forbiddenPaths.some(p => {
             const normalizedRule = this.normalizePathForMatching(p);
             const regexStr = normalizedRule
               .replace(/\./g, '\\.')
               .replace(/\*\*/g, '.*')
               .replace(/\*/g, '[^/]*');
             return new RegExp(`^${regexStr}$`, 'i').test(normalizedTarget);
          });
          if (isForbidden) return { action: rule.action, rule };
        }
      } else {
         return { action: rule.action, rule };
      }
    }

    return { action: 'allow' };
  }
}
