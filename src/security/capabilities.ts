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
  capabilities: ToolCapabilities;
}

export class CapabilityInferencer {
  public static infer(toolName: string, schema: any, description: string): ToolCapabilities {
    const name = toolName.toLowerCase();
    const desc = (description || '').toLowerCase();
    const schemaStr = JSON.stringify(schema).toLowerCase();
    const combinedStr = `${name} ${desc} ${schemaStr}`;

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

  public static hashSchema(schema: any): string {
    return crypto.createHash('sha256').update(JSON.stringify(schema)).digest('hex');
  }
}
