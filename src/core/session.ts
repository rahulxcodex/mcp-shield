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
  private allowToolsUpdate: boolean = false;

  public allowNextToolsUpdate(): void {
    this.allowToolsUpdate = true;
  }

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

      // Provenance strengthening: Detect interpreter execution and bind to package/target script
      const isInterpreter = /node(?:\.exe)?$|python(?:\.exe|\d)?$|npx(?:\.cmd)?$|bun|deno/i.test(path.basename(cmd));
      if (isInterpreter && args.length > 0) {
        for (const arg of args) {
          if (typeof arg === 'string' && (arg.endsWith('.js') || arg.endsWith('.mjs') || arg.endsWith('.cjs') || arg.endsWith('.py') || arg.endsWith('.ts'))) {
            const resolvedTarget = path.isAbsolute(arg) ? arg : path.resolve(process.cwd(), arg);
            if (fs.existsSync(resolvedTarget) && fs.statSync(resolvedTarget).isFile()) {
              const scriptStat = fs.statSync(resolvedTarget);
              hasher.update(`script:${scriptStat.size}:${fs.readFileSync(resolvedTarget)}:`);

              // Inspect adjacent package.json for immutable dependency & package identity
              let currentDir = path.dirname(resolvedTarget);
              for (let d = 0; d < 4; d++) {
                const pkgPath = path.join(currentDir, 'package.json');
                if (fs.existsSync(pkgPath)) {
                  try {
                    const pkgContent = fs.readFileSync(pkgPath, 'utf8');
                    const parsed = JSON.parse(pkgContent);
                    hasher.update(`pkg:${parsed.name}@${parsed.version}:`);
                  } catch {}
                  break;
                }
                const parent = path.dirname(currentDir);
                if (parent === currentDir) break;
                currentDir = parent;
              }
              break;
            }
          }
        }
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
      if (this.allowToolsUpdate) {
        // Legitimate dynamic tools update (e.g. notifications/tools/list_changed)
        this.initialToolsSnapshotHash = snapshotHash;
        this.registeredToolNames = new Set(tools.map(t => t.name));
        this.allowToolsUpdate = false;
      } else {
        throw new Error(`[MCP-SHIELD] SCHEMA PINNING VIOLATION: Tool list altered dynamically without expected update notice.`);
      }
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
      if (!this.allowToolsUpdate) {
        throw new Error(`[MCP-SHIELD] SCHEMA PINNING VIOLATION: Tool '${toolName}' changed its schema dynamically.`);
      }
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
