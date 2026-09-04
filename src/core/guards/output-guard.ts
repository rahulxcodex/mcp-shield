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
