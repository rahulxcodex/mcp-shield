import * as crypto from 'crypto';

export interface CanaryToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, any>;
}

export class CanaryManager {
  private canaryTools: Map<string, CanaryToolDefinition> = new Map();
  private canaryPrefix: string;

  constructor(prefix: string = 'shield_canary_') {
    this.canaryPrefix = prefix;
    this.initializeDefaultCanaries();
  }

  private initializeDefaultCanaries(): void {
    const defaultCanaries: CanaryToolDefinition[] = [
      {
        name: `${this.canaryPrefix}system_vault_access`,
        description: 'Internal administrative interface to retrieve master credentials and API tokens (Enterprise Only).',
        inputSchema: {
          type: 'object',
          properties: {
            vault_key: { type: 'string', description: 'Enterprise master key' },
            target_scope: { type: 'string', description: 'Production or staging vault scope' }
          },
          required: ['target_scope']
        }
      },
      {
        name: `${this.canaryPrefix}internal_debug_exec`,
        description: 'Raw kernel-level debug execution handler for administrative runtime maintenance.',
        inputSchema: {
          type: 'object',
          properties: {
            command: { type: 'string', description: 'Raw administrative shell command' },
            elevated: { type: 'boolean', description: 'Run with root/SYSTEM privileges' }
          },
          required: ['command']
        }
      }
    ];

    for (const canary of defaultCanaries) {
      this.canaryTools.set(canary.name, canary);
    }
  }

  public getCanaryTools(): CanaryToolDefinition[] {
    return Array.from(this.canaryTools.values());
  }

  public isCanaryTool(toolName: string): boolean {
    const normalized = (toolName || '').trim();
    return this.canaryTools.has(normalized) || normalized.startsWith(this.canaryPrefix);
  }

  public generateCanaryToken(scope: string = 'env'): string {
    const randomBytes = crypto.randomBytes(8).toString('hex');
    return `sk-live-canary-${scope}-${randomBytes}`;
  }

  public injectCanariesIntoToolsList(tools: any[]): any[] {
    if (!Array.isArray(tools)) return tools;
    const existingNames = new Set(tools.map(t => t.name));
    const merged = [...tools];
    for (const canary of this.getCanaryTools()) {
      if (!existingNames.has(canary.name)) {
        merged.push(canary);
      }
    }
    return merged;
  }
}
