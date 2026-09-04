import * as crypto from 'crypto';
import { ToolCapabilities } from './capabilities';

export interface ToolCapabilityManifest {
  toolName: string;
  description?: string;
  version?: string;
  schemaFingerprint?: string;
  allowedCapabilities: {
    filesystemRead?: boolean;
    filesystemWrite?: boolean;
    shellExecution?: boolean;
    networkAccess?: boolean;
    processSpawn?: boolean;
    secretAccess?: boolean;
    destructiveOperation?: boolean;
  };
  allowedPaths?: string[];
  allowedEgressDomains?: string[];
  allowedSecretScopes?: string[];
  maxTokenBudget?: number;
  timeoutMs?: number;
  rateLimitPerMinute?: number;
  requireHumanApproval?: boolean;
}

export type ManifestViolationReason = 
  | 'AUTHORIZED'
  | 'UNKNOWN_TOOL_BLOCKED'
  | 'CAPABILITY_VIOLATION'
  | 'PATH_SCOPE_VIOLATION'
  | 'EGRESS_SCOPE_VIOLATION'
  | 'SECRET_SCOPE_VIOLATION'
  | 'RESOURCE_BUDGET_EXCEEDED'
  | 'SCHEMA_DRIFT_DETECTED';

export interface CapabilityBrokerDecision {
  authorized: boolean;
  reasonCode: ManifestViolationReason;
  violatedCapability?: string;
  details?: string;
}

export class CapabilityManifestRegistry {
  private manifests = new Map<string, ToolCapabilityManifest>();
  private schemaFingerprints = new Map<string, string>();
  private defaultDenyUnknown: boolean;

  constructor(defaultDenyUnknown: boolean = true) {
    this.defaultDenyUnknown = defaultDenyUnknown;
  }

  public static computeSchemaFingerprint(schema: any): string {
    try {
      const canonical = JSON.stringify(schema, Object.keys(schema || {}).sort());
      return crypto.createHash('sha256').update(canonical).digest('hex');
    } catch {
      return crypto.createHash('sha256').update(String(schema)).digest('hex');
    }
  }

  public registerManifest(manifest: ToolCapabilityManifest): void {
    const key = (manifest.toolName || '').trim().toLowerCase();
    this.manifests.set(key, Object.freeze({ ...manifest }));
    if (manifest.schemaFingerprint) {
      this.schemaFingerprints.set(key, manifest.schemaFingerprint);
    }
  }

  public attestSchema(toolName: string, schema: any): { driftDetected: boolean; fingerprint: string } {
    const key = (toolName || '').trim().toLowerCase();
    const fingerprint = CapabilityManifestRegistry.computeSchemaFingerprint(schema);
    const existing = this.schemaFingerprints.get(key);

    if (existing && existing !== fingerprint) {
      return { driftDetected: true, fingerprint };
    }

    this.schemaFingerprints.set(key, fingerprint);
    return { driftDetected: false, fingerprint };
  }

  public getFingerprint(toolName: string): string | undefined {
    return this.schemaFingerprints.get((toolName || '').trim().toLowerCase());
  }

  public getManifest(toolName: string): ToolCapabilityManifest | undefined {
    return this.manifests.get((toolName || '').trim().toLowerCase());
  }

  public hasManifest(toolName: string): boolean {
    return this.manifests.has((toolName || '').trim().toLowerCase());
  }

  public hasManifests(): boolean {
    return this.manifests.size > 0;
  }

  public setDefaultDenyUnknown(deny: boolean): void {
    this.defaultDenyUnknown = deny;
  }

  public isDefaultDenyUnknown(): boolean {
    return this.defaultDenyUnknown;
  }

  /**
   * Authorizes a tool invocation against its registered capability manifest contract.
   * If the tool is unknown, returns UNKNOWN_TOOL_BLOCKED in strict/default-deny mode.
   */
  public verifyInvocation(
    toolName: string,
    args: Record<string, any>,
    inferred: Partial<ToolCapabilities>,
    options: { strictMode?: boolean } = {}
  ): CapabilityBrokerDecision {
    const key = (toolName || '').trim().toLowerCase();
    const manifest = this.manifests.get(key);
    const enforceDeny = options.strictMode !== undefined ? options.strictMode : this.defaultDenyUnknown;

    // 1. Unknown tool handling
    if (!manifest) {
      if (enforceDeny) {
        return {
          authorized: false,
          reasonCode: 'UNKNOWN_TOOL_BLOCKED',
          details: `Tool '${toolName}' has no registered or verified capability manifest contract (Default-Deny).`
        };
      }
      return { authorized: true, reasonCode: 'AUTHORIZED' };
    }

    // 2. Capability verification: Every capability inferred from input/behavior MUST be explicitly allowed in the manifest
    const allowed = manifest.allowedCapabilities || {};

    if (inferred.shellExecution && !allowed.shellExecution) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'shellExecution',
        details: `Tool '${toolName}' attempted shell execution without manifest authorization.`
      };
    }

    if (inferred.processSpawn && !allowed.processSpawn) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'processSpawn',
        details: `Tool '${toolName}' attempted process spawn without manifest authorization.`
      };
    }

    if (inferred.destructiveOperation && !allowed.destructiveOperation) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'destructiveOperation',
        details: `Tool '${toolName}' attempted destructive operation without manifest authorization.`
      };
    }

    if (inferred.networkAccess && !allowed.networkAccess) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'networkAccess',
        details: `Tool '${toolName}' attempted outbound network access without manifest authorization.`
      };
    }

    if (inferred.filesystemWrite && !allowed.filesystemWrite) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'filesystemWrite',
        details: `Tool '${toolName}' attempted filesystem write without manifest authorization.`
      };
    }

    if (inferred.filesystemRead && !allowed.filesystemRead) {
      return {
        authorized: false,
        reasonCode: 'CAPABILITY_VIOLATION',
        violatedCapability: 'filesystemRead',
        details: `Tool '${toolName}' attempted filesystem read without manifest authorization.`
      };
    }

    if (inferred.secretAccess && !allowed.secretAccess) {
      return {
        authorized: false,
        reasonCode: 'SECRET_SCOPE_VIOLATION',
        violatedCapability: 'secretAccess',
        details: `Tool '${toolName}' attempted secret restoration without manifest authorization.`
      };
    }

    // 3. Resource boundaries: Path scopes
    if (manifest.allowedPaths && manifest.allowedPaths.length > 0) {
      const targetPath = args.path || args.file || args.filename || args.targetPath || args.destination;
      if (typeof targetPath === 'string') {
        const normalized = targetPath.replace(/\\/g, '/').toLowerCase();
        const matchesAllowed = manifest.allowedPaths.some(pattern => {
          const normPattern = pattern.replace(/\\/g, '/').toLowerCase();
          if (normPattern.endsWith('/*')) {
            return normalized.startsWith(normPattern.slice(0, -2));
          }
          return normalized === normPattern || normalized.startsWith(normPattern + '/');
        });

        if (!matchesAllowed) {
          return {
            authorized: false,
            reasonCode: 'PATH_SCOPE_VIOLATION',
            details: `Target path '${targetPath}' is outside the manifest-allowed paths for tool '${toolName}'.`
          };
        }
      }
    }

    // 4. Resource boundaries: Network egress domains
    if (manifest.allowedEgressDomains && manifest.allowedEgressDomains.length > 0) {
      const targetUrl = args.url || args.endpoint || args.uri || args.host;
      if (typeof targetUrl === 'string') {
        let hostname = targetUrl.toLowerCase();
        try {
          if (targetUrl.includes('://')) {
            hostname = new URL(targetUrl).hostname.toLowerCase();
          }
        } catch {}

        const matchesDomain = manifest.allowedEgressDomains.some(dom => {
          const cleanDom = dom.toLowerCase();
          return hostname === cleanDom || hostname.endsWith('.' + cleanDom);
        });

        if (!matchesDomain) {
          return {
            authorized: false,
            reasonCode: 'EGRESS_SCOPE_VIOLATION',
            details: `Target network destination '${hostname}' is outside the manifest-allowed egress domains for tool '${toolName}'.`
          };
        }
      }
    }

    return { authorized: true, reasonCode: 'AUTHORIZED' };
  }
}
