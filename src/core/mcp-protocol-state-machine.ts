/**
 * MCP-Shield — Formal MCP Protocol State Machine
 * Compliant with Step 1 of the IP Value & VRIO Moat Roadmap:
 * - Deterministic state machine enforcement
 * - Fail-closed security boundary
 * - Ping & cancellation constraint validation
 * - Request-response envelope correctness
 */

export enum MCPProtocolState {
  CONNECTING = 'CONNECTING',
  INITIALIZING = 'INITIALIZING',
  WAITING_FOR_INITIALIZE_RESPONSE = 'WAITING_FOR_INITIALIZE_RESPONSE',
  READY = 'READY',
  DEGRADED = 'DEGRADED',
  CLOSING = 'CLOSING',
  CLOSED = 'CLOSED',
}

export interface StateTransitionEvent {
  from: MCPProtocolState;
  to: MCPProtocolState;
  trigger: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface ProtocolValidationResult {
  valid: boolean;
  errorCode?: number;
  errorMessage?: string;
  newState?: MCPProtocolState;
}

export class MCPProtocolStateMachine {
  private state: MCPProtocolState = MCPProtocolState.CONNECTING;
  private history: StateTransitionEvent[] = [];
  private initializeRequestId: string | number | null = null;
  private clientCapabilities: Record<string, any> = {};
  private serverCapabilities: Record<string, any> = {};

  constructor() {
    this.recordTransition(MCPProtocolState.CONNECTING, 'initial_connection');
  }

  public getState(): MCPProtocolState {
    return this.state;
  }

  public isReady(): boolean {
    return this.state === MCPProtocolState.READY;
  }

  public getHistory(): StateTransitionEvent[] {
    return [...this.history];
  }

  /**
   * Evaluates an incoming message against protocol lifecycle invariants.
   * Enforces that only `initialize` or `ping` are permitted before READY.
   */
  public evaluateClientMessage(message: any): ProtocolValidationResult {
    if (!message || typeof message !== 'object') {
      return {
        valid: false,
        errorCode: -32600,
        errorMessage: 'Fail-closed: malformed JSON-RPC envelope (parser failure)',
      };
    }

    const method = message.method;
    const isNotification = message.id === undefined || message.id === null;

    // Reject cancellation of initialize request
    if (method === 'notifications/cancelled' && message.params?.requestId !== undefined) {
      if (this.initializeRequestId !== null && String(message.params.requestId) === String(this.initializeRequestId)) {
        return {
          valid: false,
          errorCode: -32600,
          errorMessage: 'Protocol violation: A client MUST NOT attempt to cancel its initialize request',
        };
      }
    }

    switch (this.state) {
      case MCPProtocolState.CONNECTING:
      case MCPProtocolState.INITIALIZING: {
        if (method === 'initialize') {
          this.initializeRequestId = message.id ?? 'init-default';
          this.clientCapabilities = message.params?.capabilities || {};
          this.transition(MCPProtocolState.WAITING_FOR_INITIALIZE_RESPONSE, 'initialize_sent');
          return { valid: true, newState: this.state };
        }
        if (method === 'ping') {
          return { valid: true };
        }
        return {
          valid: false,
          errorCode: -32002,
          errorMessage: `Protocol violation: Method '${method}' rejected before initialize request`,
        };
      }

      case MCPProtocolState.WAITING_FOR_INITIALIZE_RESPONSE: {
        if (method === 'ping') {
          return { valid: true };
        }
        return {
          valid: false,
          errorCode: -32002,
          errorMessage: `Protocol violation: Method '${method}' rejected while waiting for initialize response`,
        };
      }

      case MCPProtocolState.READY: {
        // In READY state, standard tools/call, resources, prompts, ping are valid
        return { valid: true };
      }

      case MCPProtocolState.DEGRADED: {
        // In degraded state, only health checks and critical safe methods allowed
        if (method === 'ping' || method === 'tools/list') {
          return { valid: true };
        }
        return {
          valid: false,
          errorCode: -32000,
          errorMessage: `Protocol degraded: Method '${method}' blocked under degraded state`,
        };
      }

      case MCPProtocolState.CLOSING:
      case MCPProtocolState.CLOSED:
        return {
          valid: false,
          errorCode: -32000,
          errorMessage: `Protocol session is closing or closed`,
        };
    }
  }

  /**
   * Evaluates server response during initialization.
   */
  public evaluateServerMessage(message: any): ProtocolValidationResult {
    if (!message || typeof message !== 'object') {
      return {
        valid: false,
        errorCode: -32603,
        errorMessage: 'Fail-closed: malformed server response envelope',
      };
    }

    if (this.state === MCPProtocolState.WAITING_FOR_INITIALIZE_RESPONSE) {
      if (message.id !== undefined && String(message.id) === String(this.initializeRequestId)) {
        if (message.error) {
          this.transition(MCPProtocolState.DEGRADED, 'initialize_failed_by_server', { error: message.error });
          return { valid: true, newState: MCPProtocolState.DEGRADED };
        }
        if (message.result) {
          this.serverCapabilities = message.result.capabilities || {};
          this.transition(MCPProtocolState.READY, 'initialize_response_received');
          return { valid: true, newState: MCPProtocolState.READY };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Transitions to degraded state when policy/health invariants fail.
   */
  public markDegraded(reason: string): void {
    if (this.state !== MCPProtocolState.CLOSING && this.state !== MCPProtocolState.CLOSED) {
      this.transition(MCPProtocolState.DEGRADED, reason);
    }
  }

  /**
   * Orderly shutdown.
   */
  public close(reason = 'session_terminated'): void {
    this.transition(MCPProtocolState.CLOSING, reason);
    this.transition(MCPProtocolState.CLOSED, 'closed');
  }

  private transition(to: MCPProtocolState, trigger: string, metadata?: Record<string, any>): void {
    const from = this.state;
    this.state = to;
    this.recordTransition(to, trigger, metadata);
  }

  private recordTransition(to: MCPProtocolState, trigger: string, metadata?: Record<string, any>): void {
    this.history.push({
      from: this.history.length > 0 ? this.history[this.history.length - 1].to : MCPProtocolState.CONNECTING,
      to,
      trigger,
      timestamp: Date.now(),
      metadata,
    });
  }
}
