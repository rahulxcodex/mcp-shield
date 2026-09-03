import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { RegisteredTool, ToolProfile, CapabilityInferencer, ToolCapabilities } from '../security/capabilities';
import { PolicyEngine, ShieldConfig } from '../security/policy-engine';
import { SecretSanitizer } from '../security/sanitizer';
import { RateLimiter } from '../security/rate-limiter';
import { SessionLogger } from '../audit/session-logger';

export type SessionState = 'CONNECTING' | 'INITIALIZING' | 'READY' | 'DEGRADED' | 'CLOSING' | 'CLOSED';

export class SecuritySession {
  public readonly sessionId = crypto.randomUUID();
  private state: SessionState = 'CONNECTING';
  
  public serverIdentity: string = 'unknown';
  public readonly toolRegistry = new Map<string, RegisteredTool>();
  
  public readonly policyEngine: PolicyEngine;
  public readonly sanitizer: SecretSanitizer;
  public readonly rateLimiter: RateLimiter;
  public readonly logger: SessionLogger;

  constructor(
    public config: ShieldConfig,
    targetCmd: string, 
    targetArgs: string[]
  ) {
    this.policyEngine = new PolicyEngine(config);
    this.sanitizer = new SecretSanitizer(config.redaction);
    this.rateLimiter = new RateLimiter(15, 60000); // We can make this configurable later
    this.logger = new SessionLogger(); // We should pass config.audit later

    this.calculateServerIdentity(targetCmd, targetArgs);
  }

  public async start(): Promise<void> {
    this.policyEngine.start();
  }

  private initialToolsSnapshotHash: string | null = null;
  private registeredToolNames: Set<string> = new Set();

  private calculateServerIdentity(cmd: string, args: string[]) {
    try {
      let fileToHash = cmd;
      if (fs.existsSync(cmd)) {
        fileToHash = fs.realpathSync(cmd);
      } else {
        // Attempt resolution in PATH
        const pathEnv = process.env.PATH || '';
        const pathDirs = pathEnv.split(path.delimiter);
        const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.exe;.cmd;.bat').split(';') : [''];
        for (const dir of pathDirs) {
          for (const ext of exts) {
            const candidate = path.join(dir, cmd.endsWith(ext) ? cmd : cmd + ext);
            if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
              fileToHash = fs.realpathSync(candidate);
              break;
            }
          }
          if (fileToHash !== cmd) break;
        }
      }
      
      const hasher = crypto.createHash('sha256');
      if (fs.existsSync(fileToHash) && fs.statSync(fileToHash).isFile()) {
         const stat = fs.statSync(fileToHash);
         hasher.update(`${stat.size}:${stat.mtimeMs}:`);
         hasher.update(fs.readFileSync(fileToHash));
      } else {
         hasher.update(cmd);
      }
      
      hasher.update(args.join('|'));
      this.serverIdentity = hasher.digest('hex');
    } catch (e) {
      // Fallback
      this.serverIdentity = crypto.createHash('sha256').update(cmd + args.join('|')).digest('hex');
    }
  }

  public validateToolsSnapshot(tools: Array<{ name: string; description?: string; inputSchema?: any }>): void {
    // Generate deterministic signature of tools list
    const sortedSignatures = tools.map(t => {
      const schemaHash = CapabilityInferencer.hashSchema(t.inputSchema || {});
      return `${t.name}:${schemaHash}`;
    }).sort().join('|');

    const snapshotHash = crypto.createHash('sha256').update(sortedSignatures).digest('hex');

    if (this.initialToolsSnapshotHash === null) {
      this.initialToolsSnapshotHash = snapshotHash;
      this.registeredToolNames = new Set(tools.map(t => t.name));
    } else if (this.initialToolsSnapshotHash !== snapshotHash) {
      throw new Error(`[MCP-SHIELD] SCHEMA PINNING VIOLATION: Tool list altered dynamically (added/removed/reordered/modified tool capabilities).`);
    }
  }

  public transitionState(newState: SessionState): void {
    const validTransitions: Record<SessionState, SessionState[]> = {
      'CONNECTING': ['INITIALIZING', 'CLOSING', 'CLOSED'],
      'INITIALIZING': ['READY', 'DEGRADED', 'CLOSING', 'CLOSED'],
      'READY': ['DEGRADED', 'CLOSING', 'CLOSED'],
      'DEGRADED': ['READY', 'CLOSING', 'CLOSED'],
      'CLOSING': ['CLOSED'],
      'CLOSED': []
    };

    if (!validTransitions[this.state].includes(newState)) {
      throw new Error(`[MCP-SHIELD] Invalid state transition: ${this.state} -> ${newState}`);
    }

    this.state = newState;
  }

  public getState(): SessionState {
    return this.state;
  }

  public registerTool(toolName: string, description: string, schema: any): RegisteredTool {
    const hash = CapabilityInferencer.hashSchema(schema);
    
    // Check if tool already exists and if the schema changed
    const existing = this.toolRegistry.get(toolName);
    if (existing && existing.schemaHash !== hash) {
      throw new Error(`[MCP-SHIELD] SCHEMA PINNING VIOLATION: Tool '${toolName}' changed its schema dynamically.`);
    }

    const profile = CapabilityInferencer.createProfile(
      this.serverIdentity,
      toolName,
      description,
      schema,
      existing
    );

    this.toolRegistry.set(toolName, profile);
    return profile;
  }

  public updateObservedCapabilities(toolName: string, observed: Partial<ToolCapabilities>): RegisteredTool | undefined {
    const existing = this.toolRegistry.get(toolName);
    if (!existing) return undefined;

    const newObserved: ToolCapabilities = {
      filesystemRead: existing.observedCapabilities.filesystemRead || !!observed.filesystemRead,
      filesystemWrite: existing.observedCapabilities.filesystemWrite || !!observed.filesystemWrite,
      shellExecution: existing.observedCapabilities.shellExecution || !!observed.shellExecution,
      networkAccess: existing.observedCapabilities.networkAccess || !!observed.networkAccess,
      processSpawn: existing.observedCapabilities.processSpawn || !!observed.processSpawn,
      destructiveOperation: existing.observedCapabilities.destructiveOperation || !!observed.destructiveOperation,
      secretAccess: existing.observedCapabilities.secretAccess || !!observed.secretAccess
    };

    const trustLevel = CapabilityInferencer.calculateTrustLevel(
      existing.declaredCapabilities,
      existing.inferredCapabilities,
      newObserved
    );

    const updatedProfile: ToolProfile = Object.freeze({
      ...existing,
      observedCapabilities: newObserved,
      trustLevel
    });

    this.toolRegistry.set(toolName, updatedProfile);
    return updatedProfile;
  }
}
