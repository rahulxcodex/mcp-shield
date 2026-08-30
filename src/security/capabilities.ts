import * as crypto from 'crypto';

export interface ToolCapabilities {
  filesystemRead: boolean;
  filesystemWrite: boolean;
  shellExecution: boolean;
  networkAccess: boolean;
  processSpawn: boolean;
  destructiveOperation: boolean;
  secretAccess: boolean;
}

export interface RegisteredTool {
  serverId: string;
  toolName: string;
  description: string;
  inputSchema: any;
  schemaHash: string;
  declaredCapabilities: ToolCapabilities;
  inferredCapabilities: ToolCapabilities;
  observedCapabilities: ToolCapabilities;
  trustLevel: 'TRUSTED' | 'UNTRUSTED' | 'SUSPICIOUS';
  firstSeen: number;
}

export class CapabilityInferencer {
  public static infer(toolName: string, schema: any, description: string): ToolCapabilities {
    const name = toolName.toLowerCase();
    const desc = (description || '').toLowerCase();
    const schemaStr = JSON.stringify(schema).toLowerCase();

    return {
      filesystemRead: /read|cat|ls|grep|find|search|view/i.test(name) || /read file|view file|search path/i.test(desc),
      filesystemWrite: /write|edit|replace|patch|rm|delete|create|mkdir|touch|cp|mv/i.test(name) || /write to file|modify file|delete file/i.test(desc),
      shellExecution: /bash|shell|terminal|exec|run_command|do_cmd|cmd/i.test(name) || /execute command|run shell/i.test(desc),
      networkAccess: /fetch|curl|wget|request|http|api|download|network|web/i.test(name) || /make http request|fetch url/i.test(desc),
      processSpawn: /spawn|fork|exec/i.test(name) || /spawn process|execute binary/i.test(desc),
      destructiveOperation: /rm|delete|drop|truncate|format|kill|stop/i.test(name) || /permanently delete|force stop/i.test(desc),
      secretAccess: /secret|key|token|password|auth|credential/i.test(name) || /access secret|retrieve token/i.test(desc)
    };
  }

  public static getDeclared(schema: any): ToolCapabilities {
    const declared = schema?._shieldCapabilities || {};
    return {
      filesystemRead: !!declared.filesystemRead,
      filesystemWrite: !!declared.filesystemWrite,
      shellExecution: !!declared.shellExecution,
      networkAccess: !!declared.networkAccess,
      processSpawn: !!declared.processSpawn,
      destructiveOperation: !!declared.destructiveOperation,
      secretAccess: !!declared.secretAccess,
    };
  }

  public static calculateTrustLevel(declared: ToolCapabilities, inferred: ToolCapabilities): 'TRUSTED' | 'UNTRUSTED' | 'SUSPICIOUS' {
    const hasDeclarations = Object.values(declared).some(v => v === true);
    if (!hasDeclarations) return 'UNTRUSTED'; // No attestation provided
    
    // If inferred has a capability that declared DOES NOT have, it's suspicious
    for (const key of Object.keys(declared) as (keyof ToolCapabilities)[]) {
      if (inferred[key] && !declared[key]) {
        return 'SUSPICIOUS';
      }
    }
    return 'TRUSTED';
  }

  public static hashSchema(schema: any): string {
    return crypto.createHash('sha256').update(JSON.stringify(schema)).digest('hex');
  }
}
