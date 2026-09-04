import { SecuritySession } from '../session';
import { CanaryManager } from '../../security/canary';
import { ProtocolValidator, ProtocolValidationResult } from '../protocol-validator';

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

  constructor(
    private session: SecuritySession,
    private canaryManager: CanaryManager
  ) {}

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

    // 3. Whole-envelope DLP sanitization
    if (message.result) {
      const resultStr = JSON.stringify(message.result);
      const sanitizedStr = this.session.sanitizer.sanitize(resultStr);
      message.result = JSON.parse(sanitizedStr);
    }

    if (message.error) {
      const errStr = JSON.stringify(message.error);
      const sanitizedErrStr = this.session.sanitizer.sanitize(errStr);
      message.error = JSON.parse(sanitizedErrStr);
    }

    if (message.params) {
      const paramsStr = JSON.stringify(message.params);
      const sanitizedParamsStr = this.session.sanitizer.sanitize(paramsStr);
      message.params = JSON.parse(sanitizedParamsStr);
    }

    if (message.method === 'notifications/tools/list_changed') {
      this.session.allowNextToolsUpdate();
    }

    return {
      allowed: true,
      message
    };
  }
}
