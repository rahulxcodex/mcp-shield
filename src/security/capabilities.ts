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

export type ExecutionClass = 'shell' | 'binary' | 'script' | 'filesystem_write' | 'filesystem_read' | 'network' | 'secret' | 'destructive';

export interface ToolProfile {
  readonly serverId: string;
  readonly toolName: string;
  readonly description: string;
  readonly inputSchema: any;
  readonly schemaHash: string;
  readonly capabilities: ToolCapabilities;
  readonly executionClasses: readonly ExecutionClass[];
  readonly declaredCapabilities: ToolCapabilities;
  readonly inferredCapabilities: ToolCapabilities;
  readonly observedCapabilities: ToolCapabilities;
  readonly trustLevel: 'TRUSTED' | 'UNTRUSTED' | 'SUSPICIOUS';
  readonly firstSeen: number;
}

export type RegisteredTool = ToolProfile;

export class CapabilityInferencer {
  /**
   * Infer tool capabilities using Schema-Driven First, Name/Description Second methodology.
   * Parameter names, schema types, and formats are weighted highest to prevent evasion
   * through deceptive tool naming (e.g. tool named `calculate_metrics` taking a `command` argument).
   */
  public static infer(toolName: string, schema: any, description: string): ToolCapabilities {
    const name = (toolName || '').toLowerCase();
    const desc = (description || '').toLowerCase();

    // 1. SCHEMA INSPECTION (Priority 1)
    const propertyNames: string[] = [];
    const propertyDescs: string[] = [];
    const propertyFormats: string[] = [];

    const inspectSchemaObject = (obj: any) => {
      if (!obj || typeof obj !== 'object') return;
      
      if (obj.properties && typeof obj.properties === 'object') {
        for (const [propName, propDef] of Object.entries<any>(obj.properties)) {
          propertyNames.push(propName.toLowerCase());
          if (propDef && typeof propDef === 'object') {
            if (propDef.description) propertyDescs.push(String(propDef.description).toLowerCase());
            if (propDef.format) propertyFormats.push(String(propDef.format).toLowerCase());
          }
        }
      }

      if (Array.isArray(obj.required)) {
        for (const req of obj.required) {
          if (typeof req === 'string') propertyNames.push(req.toLowerCase());
        }
      }
    };

    inspectSchemaObject(schema);

    const schemaHasProp = (regex: RegExp) => propertyNames.some(p => regex.test(p));
    const schemaHasDesc = (regex: RegExp) => propertyDescs.some(d => regex.test(d));
    const schemaHasFormat = (regex: RegExp) => propertyFormats.some(f => regex.test(f));

    // Schema-level Clues
    const schemaShell = schemaHasProp(/^(command|cmd|script|bash|shell_cmd|exec_command|eval|code)$/i) || schemaHasDesc(/shell command|bash script|executable command/i);
    const schemaFsWrite = schemaHasProp(/^(content|text|patch|write_path|destination|dest|output_file|overwrite|target_path|file_content)$/i) || schemaHasDesc(/file content|write to|destination path/i);
    const schemaFsRead = schemaHasProp(/^(path|file|filepath|dir|directory|read_path|folder|filename|source_file|source_path)$/i) || schemaHasFormat(/^(path|file|uri)$/i) || schemaHasDesc(/file path|directory path|source file/i);
    const schemaNetwork = schemaHasProp(/^(url|uri|endpoint|domain|host|hostname|webhook|http_method|headers)$/i) || schemaHasFormat(/^uri$/i) || schemaHasDesc(/url|http endpoint|web address/i);
    const schemaProcess = schemaHasProp(/^(binary|executable|process|spawn_args|env_vars|arguments)$/i) || schemaHasDesc(/spawn process|execute binary/i);
    const schemaDestructive = schemaHasProp(/^(force|recursive|drop_tables|purge|delete_all|truncate)$/i) || schemaHasDesc(/force delete|recursive delete|purge/i);
    const schemaSecret = schemaHasProp(/^(api_key|secret|token|password|auth_token|credential|private_key|access_token)$/i) || schemaHasDesc(/api key|secret token|auth password/i);

    // 2. NAME & DESCRIPTION MATCHING (Priority 2 & 3)
    const nameFsRead = /read|cat|ls|grep|find|search|view|get_file|list_dir/i.test(name);
    const descFsRead = /read file|view file|search path|list contents|inspect directory/i.test(desc);

    const nameFsWrite = /write|edit|replace|patch|rm|delete|create|mkdir|touch|cp|mv/i.test(name);
    const descFsWrite = /write to file|modify file|delete file|create directory|edit code/i.test(desc);

    const nameShell = /bash|shell|terminal|exec|run_command|do_cmd|cmd/i.test(name);
    const descShell = /execute command|run shell|run bash|execute in terminal/i.test(desc);

    const nameNetwork = /fetch|curl|wget|request|http|api|download|network|web/i.test(name);
    const descNetwork = /make http request|fetch url|download from web|send api request/i.test(desc);

    const nameProcess = /spawn|fork|exec/i.test(name);
    const descProcess = /spawn process|execute binary|start daemon/i.test(desc);

    const nameDestructive = /rm|delete|drop|truncate|format|kill|stop|destroy/i.test(name);
    const descDestructive = /permanently delete|force stop|drop table|destroy workspace/i.test(desc);

    const nameSecret = /secret|key|token|password|auth|credential/i.test(name);
    const descSecret = /access secret|retrieve token|manage credentials/i.test(desc);

    return {
      filesystemRead: schemaFsRead || nameFsRead || descFsRead,
      filesystemWrite: schemaFsWrite || nameFsWrite || descFsWrite,
      shellExecution: schemaShell || nameShell || descShell,
      networkAccess: schemaNetwork || nameNetwork || descNetwork,
      processSpawn: schemaProcess || nameProcess || descProcess,
      destructiveOperation: schemaDestructive || nameDestructive || descDestructive,
      secretAccess: schemaSecret || nameSecret || descSecret
    };
  }

  public static deriveExecutionClasses(caps: ToolCapabilities): ExecutionClass[] {
    const classes: ExecutionClass[] = [];
    if (caps.shellExecution) classes.push('shell');
    if (caps.processSpawn) classes.push('binary');
    if (caps.filesystemWrite) classes.push('filesystem_write');
    if (caps.filesystemRead) classes.push('filesystem_read');
    if (caps.networkAccess) classes.push('network');
    if (caps.secretAccess) classes.push('secret');
    if (caps.destructiveOperation) classes.push('destructive');
    return classes;
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

  public static calculateTrustLevel(
    declared: ToolCapabilities,
    inferred: ToolCapabilities,
    observed?: ToolCapabilities
  ): 'TRUSTED' | 'UNTRUSTED' | 'SUSPICIOUS' {
    const hasDeclarations = Object.values(declared).some(v => v === true);
    if (!hasDeclarations) return 'UNTRUSTED'; // No attestation provided
    
    // If inferred has a capability that declared DOES NOT have, it's suspicious
    for (const key of Object.keys(declared) as (keyof ToolCapabilities)[]) {
      if (inferred[key] && !declared[key]) {
        return 'SUSPICIOUS';
      }
      if (observed && observed[key] && !declared[key]) {
        return 'UNTRUSTED'; // Violated trust at runtime
      }
    }
    return 'TRUSTED';
  }

  public static createProfile(
    serverId: string,
    toolName: string,
    description: string,
    schema: any,
    existingProfile?: ToolProfile
  ): ToolProfile {
    const hash = this.hashSchema(schema);
    const inferred = this.infer(toolName, schema, description);
    const declared = this.getDeclared(schema);
    const observed: ToolCapabilities = existingProfile
      ? { ...existingProfile.observedCapabilities }
      : {
          filesystemRead: false,
          filesystemWrite: false,
          shellExecution: false,
          networkAccess: false,
          processSpawn: false,
          destructiveOperation: false,
          secretAccess: false
        };

    const trustLevel = this.calculateTrustLevel(declared, inferred, observed);
    const executionClasses = this.deriveExecutionClasses(inferred);

    return Object.freeze({
      serverId,
      toolName,
      description: description || '',
      inputSchema: schema,
      schemaHash: hash,
      capabilities: inferred,
      executionClasses,
      declaredCapabilities: declared,
      inferredCapabilities: inferred,
      observedCapabilities: observed,
      trustLevel,
      firstSeen: existingProfile ? existingProfile.firstSeen : Date.now()
    });
  }

  public static hashSchema(schema: any): string {
    return crypto.createHash('sha256').update(JSON.stringify(schema)).digest('hex');
  }
}
