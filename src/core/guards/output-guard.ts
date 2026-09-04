import { SecuritySession } from '../session';
import { CanaryManager } from '../../security/canary';
import { ProtocolValidator, ProtocolValidationResult } from '../protocol-validator';
import { ResponseSecurityPipeline } from '../../security/response/response-security-pipeline';
import { McpSurfaceInspector } from '../../security/protocol/mcp-surface-inspector';

export interface ProcessOutboundResult {
  allowed: boolean;
  message?: any;
  id?: any;
  errorCode?: number;
  errorMessage?: string;
  schemaViolation?: boolean;
}

export class OutputGuard {
  private validator = new ProtocolValidator();
  private responsePipeline: ResponseSecurityPipeline;
  private surfaceInspector: McpSurfaceInspector;

  constructor(
    private session: SecuritySession,
    private canaryManager: CanaryManager,
    responsePipeline?: ResponseSecurityPipeline,
    surfaceInspector?: McpSurfaceInspector
  ) {
    this.responsePipeline = responsePipeline || new ResponseSecurityPipeline();
    this.surfaceInspector = surfaceInspector || new McpSurfaceInspector();
  }

  public processOutboundMessage(
    rawBuffer: Buffer,
    onLog: (event: any) => void,
    onKillChild: () => void
  ): ProcessOutboundResult {
    let message: any = null;
    try {
      message = JSON.parse(rawBuffer.toString('utf8'));
    } catch {
      onLog({ type: 'parse_error', reason: 'Failed to parse JSON from outbound stream, dropping payload.' });
      return { allowed: false, errorCode: -32700, errorMessage: 'Parse error: Invalid JSON from child' };
    }

    // 1. Output amplification check
    const valResult = this.validator.validateOutbound(message);
    if (!valResult.valid) {
      onLog({ type: 'output_amplification_blocked', reason: valResult.errorMessage });
      return {
        allowed: false,
        id: message?.id,
        errorCode: valResult.errorCode,
        errorMessage: valResult.errorMessage
      };
    }

    // 2. Intercept tools/list response
    if (message.id !== undefined && message.result && message.result.tools) {
      message.result.tools = this.canaryManager.injectCanariesIntoToolsList(message.result.tools);

      try {
        // Pin full tool list snapshot
        this.session.validateToolsSnapshot(message.result.tools);
      } catch (e: any) {
        onLog({ type: 'schema_violation', reason: e.message });
        onKillChild();
        return {
          allowed: false,
          id: message.id,
          schemaViolation: true,
          errorCode: -32603,
          errorMessage: `SCHEMA PINNING VIOLATION: ${e.message}`
        };
      }

      for (const tool of message.result.tools) {
        try {
          this.session.registerTool(tool.name, tool.description || '', tool.inputSchema || {});
        } catch (e: any) {
          onLog({ type: 'schema_violation', reason: e.message });
          onKillChild();
          return {
            allowed: false,
            id: message.id,
            schemaViolation: true,
            errorCode: -32603,
            errorMessage: `SCHEMA VIOLATION: ${e.message}`
          };
        }
      }
    }

    // 2.1 Surface Security Inspection (initialize instructions, resources/list, resources/read, prompts/list, prompts/get)
    if (message.result) {
      if (typeof message.result.instructions === 'string') {
        const instrRes = this.surfaceInspector.inspectServerInstructions(message.result.instructions);
        if (!instrRes.isSafe) {
          onLog({
            type: 'surface_violation_blocked',
            surface: 'server/instructions',
            findings: instrRes.findings
          });
          return {
            allowed: false,
            id: message.id,
            errorCode: -32603,
            errorMessage: `SURFACE_SECURITY_BLOCKED: ${instrRes.findings[0]?.explanation || 'Dangerous instruction in server capabilities'}`
          };
        }
      }

      if (Array.isArray(message.result.resources)) {
        const resListEval = this.surfaceInspector.inspectResourcesList(message.result.resources);
        if (!resListEval.isSafe) {
          onLog({
            type: 'surface_violation_blocked',
            surface: 'resources/list',
            findings: resListEval.findings
          });
          return {
            allowed: false,
            id: message.id,
            errorCode: -32603,
            errorMessage: `SURFACE_SECURITY_BLOCKED: ${resListEval.findings[0]?.explanation || 'Malicious resource definition in resources/list'}`
          };
        }
      }

      if (Array.isArray(message.result.contents)) {
        const uri = message.result.uri || (typeof message.id === 'string' ? message.id : 'unknown');
        const contentEval = this.surfaceInspector.inspectResourceReadResponse(uri, message.result.contents);
        if (!contentEval.isSafe) {
          onLog({
            type: 'surface_violation_blocked',
            surface: 'resources/read',
            findings: contentEval.findings
          });
          return {
            allowed: false,
            id: message.id,
            errorCode: -32603,
            errorMessage: `SURFACE_SECURITY_BLOCKED: ${contentEval.findings[0]?.explanation || 'Poisoned content in resources/read'}`
          };
        }
      }

      if (Array.isArray(message.result.prompts)) {
        const promptListEval = this.surfaceInspector.inspectPromptsList(message.result.prompts);
        if (!promptListEval.isSafe) {
          onLog({
            type: 'surface_violation_blocked',
            surface: 'prompts/list',
            findings: promptListEval.findings
          });
          return {
            allowed: false,
            id: message.id,
            errorCode: -32603,
            errorMessage: `SURFACE_SECURITY_BLOCKED: ${promptListEval.findings[0]?.explanation || 'Dangerous prompt in prompts/list'}`
          };
        }
      }

      if (Array.isArray(message.result.messages)) {
        const promptName = message.result.name || (typeof message.id === 'string' ? message.id : 'prompt');
        const promptGetEval = this.surfaceInspector.inspectPromptGetResponse(promptName, message.result);
        if (!promptGetEval.isSafe) {
          onLog({
            type: 'surface_violation_blocked',
            surface: 'prompts/get',
            findings: promptGetEval.findings
          });
          return {
            allowed: false,
            id: message.id,
            errorCode: -32603,
            errorMessage: `SURFACE_SECURITY_BLOCKED: ${promptGetEval.findings[0]?.explanation || 'Dangerous prompt template in prompts/get'}`
          };
        }
      }
    }

    // 3. Whole-envelope DLP sanitization without redundant re-serialization cycles
    if (message.result) {
      this.sanitizeInPlace(message.result);
    }
    if (message.error) {
      this.sanitizeInPlace(message.error);
    }
    if (message.params) {
      this.sanitizeInPlace(message.params);
    }

    // 4. Response-Side Semantic Inspection (Indirect prompt injection, malicious URLs, steganography)
    if (message.result && !message.result.tools) {
      const respEval = this.responsePipeline.evaluateResponse('tool_output', message.result);
      if (respEval.action === 'BLOCK') {
        onLog({
          type: 'response_poisoning_blocked',
          reason: respEval.findings.map(f => f.explanation).join('; '),
          findings: respEval.findings,
        });

        return {
          allowed: false,
          id: message.id,
          errorCode: -32603,
          errorMessage: `RESPONSE_POISONING_BLOCKED: ${respEval.findings[0]?.explanation || 'Dangerous instruction or payload in tool response'}`
        };
      }
    }

    if (message.method === 'notifications/tools/list_changed') {
      this.session.allowNextToolsUpdate();
    }

    return {
      allowed: true,
      message
    };
  }

  private sanitizeInPlace(target: any, depth = 0): void {
    if (!target || depth > 20) return;

    if (Array.isArray(target)) {
      for (let i = 0; i < target.length; i++) {
        if (typeof target[i] === 'string') {
          target[i] = this.session.sanitizer.sanitize(target[i]);
        } else if (typeof target[i] === 'object' && target[i] !== null) {
          this.sanitizeInPlace(target[i], depth + 1);
        }
      }
      return;
    }

    if (typeof target === 'object') {
      for (const key of Object.keys(target)) {
        const val = target[key];
        if (typeof val === 'string') {
          target[key] = this.session.sanitizer.sanitize(val);
        } else if (typeof val === 'object' && val !== null) {
          this.sanitizeInPlace(val, depth + 1);
        }
      }
    }
  }
}
