import * as fs from 'fs';
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
      this.loadConfig();
    }
    return this.config!;
  }

  public evaluateToolCall(toolName: string, args: Record<string, any>): { action: PolicyRule['action']; rule?: PolicyRule } {
    if (!this.config) this.loadConfig();

    for (const rule of this.config!.rules) {
      const isTarget = rule.targetTools.some(t => {
        if (t.includes('*')) {
          const regex = new RegExp('^' + t.replace(/\*/g, '.*') + '$');
          return regex.test(toolName);
        }
        return t === toolName;
      });

      if (!isTarget) continue;

      if (rule.matchers) {
        if (rule.matchers.pathMatches && (args.path || args.file || args.filename)) {
          const targetPath = (args.path || args.file || args.filename) as string;
          const isForbidden = rule.matchers.pathMatches.forbiddenPaths.some(p => {
             const regexStr = p.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
             return new RegExp(`^${regexStr}$`).test(targetPath) || new RegExp(regexStr).test(targetPath);
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
