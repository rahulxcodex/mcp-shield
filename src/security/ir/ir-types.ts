export type CommandInterpreterType = 'BASH' | 'POWERSHELL' | 'CMD' | 'GENERIC';

export type SecurityActionType =
  | 'READ_FILE'
  | 'WRITE_FILE'
  | 'DELETE_FILE'
  | 'NETWORK_REQUEST'
  | 'EXECUTE_PROCESS'
  | 'ENCODE_DECODE'
  | 'ENV_ACCESS'
  | 'PRIVILEGE_ESCALATION'
  | 'PERSISTENCE';

export interface BaseSecurityAction {
  type: SecurityActionType;
  rawSnippet?: string;
}

export interface ReadFileAction extends BaseSecurityAction {
  type: 'READ_FILE';
  path: string;
  sensitive?: boolean;
}

export interface WriteFileAction extends BaseSecurityAction {
  type: 'WRITE_FILE';
  path: string;
  destructive?: boolean;
}

export interface DeleteFileAction extends BaseSecurityAction {
  type: 'DELETE_FILE';
  path: string;
  rootOrSystem?: boolean;
  recursive?: boolean;
}

export interface NetworkRequestAction extends BaseSecurityAction {
  type: 'NETWORK_REQUEST';
  destination: string;
  port?: number;
  scheme?: string;
}

export interface ExecuteProcessAction extends BaseSecurityAction {
  type: 'EXECUTE_PROCESS';
  binary: string;
  arguments: string[];
  elevated?: boolean;
}

export interface EncodeDecodeAction extends BaseSecurityAction {
  type: 'ENCODE_DECODE';
  algorithm: 'BASE64' | 'HEX' | 'UNKNOWN';
  direction: 'ENCODE' | 'DECODE';
  payload?: string;
}

export interface EnvAccessAction extends BaseSecurityAction {
  type: 'ENV_ACCESS';
  variableName: string;
  isSecret?: boolean;
}

export interface PrivilegeEscalationAction extends BaseSecurityAction {
  type: 'PRIVILEGE_ESCALATION';
  method: string;
}

export interface PersistenceAction extends BaseSecurityAction {
  type: 'PERSISTENCE';
  method: string;
}

export type SecurityActionIR =
  | ReadFileAction
  | WriteFileAction
  | DeleteFileAction
  | NetworkRequestAction
  | ExecuteProcessAction
  | EncodeDecodeAction
  | EnvAccessAction
  | PrivilegeEscalationAction
  | PersistenceAction;

export interface SecurityCommandIR {
  interpreter: CommandInterpreterType;
  rawCommand: string;
  normalizedCommand: string;
  actions: SecurityActionIR[];
  metadata?: Record<string, any>;
}

export interface SemanticThreatFinding {
  ruleId: string;
  category: 'FILESYSTEM' | 'PROCESS' | 'NETWORK' | 'CREDENTIAL' | 'PERSISTENCE';
  severity: number;
  explanation: string;
  action: SecurityActionIR;
}
