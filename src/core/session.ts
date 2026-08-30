import * as crypto from 'crypto';
import * as fs from 'fs';
import { RegisteredTool, CapabilityInferencer, ToolCapabilities } from '../security/capabilities';
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

  private calculateServerIdentity(cmd: string, args: string[]) {
    try {
      // Very naive approach: If it's a local file, hash it. Otherwise hash the command strings.
      let fileToHash = cmd;
      if (fs.existsSync(cmd)) {
        fileToHash = fs.realpathSync(cmd);
      }
      
      const hasher = crypto.createHash('sha256');
      if (fs.existsSync(fileToHash) && fs.statSync(fileToHash).isFile()) {
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

    const inferredCapabilities = CapabilityInferencer.infer(toolName, schema, description);
    const declaredCapabilities = CapabilityInferencer.getDeclared(schema);
    const trustLevel = CapabilityInferencer.calculateTrustLevel(declaredCapabilities, inferredCapabilities);
    
    const registered: RegisteredTool = {
      serverId: this.serverIdentity,
      toolName,
      description,
      inputSchema: schema,
      schemaHash: hash,
      declaredCapabilities,
      inferredCapabilities,
      observedCapabilities: existing ? existing.observedCapabilities : {
        filesystemRead: false,
        filesystemWrite: false,
        shellExecution: false,
        networkAccess: false,
        processSpawn: false,
        destructiveOperation: false,
        secretAccess: false
      },
      trustLevel,
      firstSeen: existing ? existing.firstSeen : Date.now()
    };

    this.toolRegistry.set(toolName, registered);
    return registered;
  }
}
