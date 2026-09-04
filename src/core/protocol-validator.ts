export interface ProtocolValidationResult {
  valid: boolean;
  errorCode?: number;
  errorMessage?: string;
}

export interface ProtocolValidatorConfig {
  maxDepth?: number;
  maxKeys?: number;
  maxOutboundBytes?: number;
}

export class ProtocolValidator {
  private readonly MAX_RECURSION_DEPTH: number;
  private readonly MAX_KEY_COUNT: number;
  private readonly MAX_OUTPUT_BYTES: number;
  private pendingRequests = new Map<string | number, { method: string; timestamp: number }>();

  private readonly MAX_ARGUMENT_BYTES: number;

  constructor(config: ProtocolValidatorConfig = {}) {
    this.MAX_RECURSION_DEPTH = config.maxDepth ?? 32;
    this.MAX_KEY_COUNT = config.maxKeys ?? 5000;
    this.MAX_OUTPUT_BYTES = config.maxOutboundBytes ?? (1024 * 1024);
    this.MAX_ARGUMENT_BYTES = (config as any).maxArgumentBytes ?? (512 * 1024);
  }

  /**
   * Validates inbound JSON-RPC 2.0 message against protocol specification and complexity bounds.
   */
  public validateInbound(message: any): ProtocolValidationResult {
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      return { valid: false, errorCode: -32600, errorMessage: 'Invalid Request: Message must be a non-null object' };
    }

    // 1. JSON-RPC version enforcement
    if (message.jsonrpc !== '2.0') {
      return { valid: false, errorCode: -32600, errorMessage: 'Invalid Request: jsonrpc property must be exactly "2.0"' };
    }

    // 2. ID validation (if present)
    if (message.id !== undefined && message.id !== null) {
      const idType = typeof message.id;
      if (idType !== 'string' && idType !== 'number') {
        return { valid: false, errorCode: -32600, errorMessage: 'Invalid Request: id must be a string or number' };
      }
      if (idType === 'number' && (!Number.isInteger(message.id) || !Number.isFinite(message.id))) {
        return { valid: false, errorCode: -32600, errorMessage: 'Invalid Request: numeric id must be a finite integer' };
      }

      // Check for duplicate pending requests
      if (this.pendingRequests.has(message.id)) {
        return { valid: false, errorCode: -32600, errorMessage: `Invalid Request: Duplicate pending request id "${message.id}"` };
      }
    }

    // 3. Method validation
    if (typeof message.method !== 'string' || !message.method.trim()) {
      return { valid: false, errorCode: -32600, errorMessage: 'Invalid Request: method must be a non-empty string' };
    }

    // 4. Complexity & nesting depth validation (DoS prevention)
    const complexityCheck = this.checkComplexity(message, 0, { keys: 0 });
    if (!complexityCheck.valid) {
      return complexityCheck;
    }

    // 5. Method-specific MCP payload validation
    const methodValidation = this.validateMethodPayload(message.method, message.params);
    if (!methodValidation.valid) {
      return methodValidation;
    }

    // Record request for correlation tracking
    if (message.id !== undefined && message.id !== null) {
      this.pendingRequests.set(message.id, { method: message.method, timestamp: Date.now() });
    }

    return { valid: true };
  }

  private validateMethodPayload(method: string, params: any): ProtocolValidationResult {
    switch (method) {
      case 'initialize':
        if (params !== undefined && params !== null) {
          if (typeof params !== 'object' || Array.isArray(params)) {
            return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for initialize: must be an object' };
          }
          if (params.protocolVersion !== undefined && typeof params.protocolVersion !== 'string') {
            return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for initialize: protocolVersion must be a string' };
          }
        }
        break;

      case 'tools/call':
        if (!params || typeof params !== 'object' || Array.isArray(params)) {
          return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for tools/call: must be an object' };
        }
        if (typeof params.name !== 'string' || !params.name.trim()) {
          return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for tools/call: "name" must be a non-empty string' };
        }
        if (params.arguments !== undefined && (typeof params.arguments !== 'object' || params.arguments === null || Array.isArray(params.arguments))) {
          return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for tools/call: "arguments" must be an object' };
        }
        if (params.arguments) {
          try {
            const argSize = JSON.stringify(params.arguments).length;
            if (argSize > this.MAX_ARGUMENT_BYTES) {
              return { valid: false, errorCode: -32600, errorMessage: `Argument payload size (${Math.round(argSize / 1024)} KB) exceeds maximum allowed ${Math.round(this.MAX_ARGUMENT_BYTES / 1024)} KB limit` };
            }
          } catch {}
        }
        break;

      case 'tools/list':
        if (params !== undefined && params !== null && (typeof params !== 'object' || Array.isArray(params))) {
          return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for tools/list: must be an object' };
        }
        break;

      case 'ping':
        if (params !== undefined && params !== null && (typeof params !== 'object' || Array.isArray(params))) {
          return { valid: false, errorCode: -32602, errorMessage: 'Invalid params for ping: must be an object' };
        }
        break;
    }

    return { valid: true };
  }

  /**
   * Validates outbound JSON-RPC response and enforces output amplification limits.
   */
  public validateOutbound(message: any, maxOutputBytes = this.MAX_OUTPUT_BYTES): ProtocolValidationResult {
    if (!message || typeof message !== 'object') {
      return { valid: false, errorCode: -32603, errorMessage: 'Internal Error: Outbound payload must be an object' };
    }

    // Check correlation if this is a response with an id
    if (message.id !== undefined && message.id !== null) {
      this.pendingRequests.delete(message.id);
    }

    // Output amplification check: Prevent huge outputs from crashing the host LLM
    try {
      const serialized = JSON.stringify(message);
      if (serialized.length > maxOutputBytes) {
        return {
          valid: false,
          errorCode: -32000,
          errorMessage: `OUTPUT_AMPLIFICATION_BLOCKED: Tool output size (${Math.round(serialized.length / 1024)} KB) exceeds the maximum allowed ${Math.round(maxOutputBytes / 1024)} KB limit.`
        };
      }
    } catch (err: any) {
      return { valid: false, errorCode: -32603, errorMessage: `Serialization Error: ${err.message}` };
    }

    return { valid: true };
  }

  public getPendingCount(): number {
    return this.pendingRequests.size;
  }

  public clearPending(): void {
    this.pendingRequests.clear();
  }

  private checkComplexity(obj: any, depth: number, counter: { keys: number }): ProtocolValidationResult {
    if (depth > this.MAX_RECURSION_DEPTH) {
      return {
        valid: false,
        errorCode: -32600,
        errorMessage: `JSON-RPC nesting depth limit (${this.MAX_RECURSION_DEPTH}) exceeded`
      };
    }

    if (obj && typeof obj === 'object') {
      const keys = Object.keys(obj);
      counter.keys += keys.length;
      if (counter.keys > this.MAX_KEY_COUNT) {
        return {
          valid: false,
          errorCode: -32600,
          errorMessage: `JSON-RPC property key count budget (${this.MAX_KEY_COUNT}) exceeded`
        };
      }

      for (const k of keys) {
        const val = obj[k];
        if (val && typeof val === 'object') {
          const res = this.checkComplexity(val, depth + 1, counter);
          if (!res.valid) return res;
        }
      }
    }

    return { valid: true };
  }
}
