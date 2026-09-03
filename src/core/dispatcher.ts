export type RequestHandler = (message: any) => Promise<void>;

export interface DispatcherConfig {
  maxQueueDepth?: number;
  maxInflightRequests?: number;
  queueTimeoutMs?: number;
}

interface QueuedMessage {
  message: any;
  queuedAt: number;
}

export class RequestDispatcher {
  private queue: QueuedMessage[] = [];
  private inflight = 0;
  private inflightIds = new Set<string | number>();
  
  private maxQueueDepth: number;
  private maxInflightRequests: number;
  private queueTimeoutMs: number;

  constructor(
    private handler: RequestHandler,
    private errorCallback?: (message: any, code: number, errorMsg: string) => void,
    config?: DispatcherConfig
  ) {
    this.maxQueueDepth = config?.maxQueueDepth || 1000;
    this.maxInflightRequests = config?.maxInflightRequests || 10;
    this.queueTimeoutMs = config?.queueTimeoutMs || 30000;
  }

  public enqueue(message: any): void {
    if (!this.isValidJsonRpc(message)) {
      if (this.errorCallback && message && message.id !== undefined && message.id !== null) {
        this.errorCallback(message, -32600, 'Invalid JSON-RPC Request: missing jsonrpc version or method');
      }
      return; 
    }

    // Duplicate Request-ID Protection for inflight requests
    if (message.id !== undefined && message.id !== null) {
      if (this.inflightIds.has(message.id)) {
        if (this.errorCallback) {
          this.errorCallback(message, -32600, `Duplicate Request ID: Request id '${message.id}' is already in flight`);
        }
        return;
      }
    }

    if (this.queue.length >= this.maxQueueDepth) {
      if (message.id !== undefined && message.id !== null) {
        if (this.errorCallback) {
          this.errorCallback(message, -32000, 'Server busy: Request queue is full (Backpressure)');
        }
      } else {
        // Notification dropped due to backpressure - log warning if callback provided
        if (this.errorCallback) {
          this.errorCallback(message, -32000, 'Notification dropped: Request queue is full (Backpressure)');
        }
      }
      return;
    }

    this.queue.push({ message, queuedAt: Date.now() });
    this.scheduleDrain();
  }

  private isValidJsonRpc(message: any): boolean {
    if (!message || typeof message !== 'object') return false;
    if (message.jsonrpc !== '2.0') return false;
    
    const hasMethod = typeof message.method === 'string';
    const hasResult = 'result' in message;
    const hasError = 'error' in message;
    
    if (hasMethod && (hasResult || hasError)) return false;
    if (!hasMethod && !hasResult && !hasError) return false;
    
    if (hasMethod) {
       if (message.params !== undefined && typeof message.params !== 'object' && !Array.isArray(message.params)) return false;
    }
    
    if ('id' in message) {
       const type = typeof message.id;
       if (type !== 'string' && type !== 'number' && message.id !== null) return false;
    }
    
    if (hasError && (typeof message.error !== 'object' || message.error === null || typeof message.error.code !== 'number' || typeof message.error.message !== 'string')) return false;

    return true;
  }

  private scheduleDrain(): void {
    while (this.inflight < this.maxInflightRequests && this.queue.length > 0) {
      const item = this.queue.shift();
      if (!item) break;

      const { message, queuedAt } = item;
      const now = Date.now();

      if (now - queuedAt > this.queueTimeoutMs) {
        if (message.id !== undefined && message.id !== null) {
          if (this.errorCallback) {
            this.errorCallback(message, -32000, 'Server busy: Request timed out in queue');
          }
        }
        continue;
      }

      this.executeMessage(message);
    }
  }

  private async executeMessage(message: any): Promise<void> {
    const hasId = message.id !== undefined && message.id !== null;
    if (hasId) {
      this.inflightIds.add(message.id);
    }
    this.inflight++;

    try {
      await this.handler(message);
    } catch (err) {
      console.error('[MCP-SHIELD] Dispatcher unhandled error:', err);
    } finally {
      this.inflight--;
      if (hasId) {
        this.inflightIds.delete(message.id);
      }
      this.scheduleDrain();
    }
  }

  public clear(): void {
    this.queue = [];
    this.inflight = 0;
    this.inflightIds.clear();
  }
}
