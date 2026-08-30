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
      if (this.errorCallback && message && message.id) {
        this.errorCallback(message, -32600, 'Invalid JSON-RPC Request: missing jsonrpc version or method');
      }
      return; 
    }

    if (this.queue.length >= this.maxQueueDepth) {
      if (this.errorCallback && message.id) {
        this.errorCallback(message, -32000, 'Server busy: Request queue is full (Backpressure)');
      }
      return;
    }

    this.queue.push({ message, queuedAt: Date.now() });
    this.processNext();
  }

  private isValidJsonRpc(message: any): boolean {
    if (!message || typeof message !== 'object') return false;
    if (message.jsonrpc !== '2.0') return false;
    if (!message.method || typeof message.method !== 'string') return false;
    if (message.params !== undefined && typeof message.params !== 'object') return false;
    return true;
  }

  private async processNext(): Promise<void> {
    if (this.inflight >= this.maxInflightRequests || this.queue.length === 0) {
      return;
    }

    const item = this.queue.shift();
    if (!item) return;

    const { message, queuedAt } = item;
    const now = Date.now();

    if (now - queuedAt > this.queueTimeoutMs) {
      if (this.errorCallback && message.id) {
        this.errorCallback(message, -32000, 'Server busy: Request timed out in queue');
      }
      setImmediate(() => this.processNext());
      return;
    }

    this.inflight++;
    try {
      await this.handler(message);
    } catch (err) {
      console.error('[MCP-SHIELD] Dispatcher unhandled error:', err);
    } finally {
      this.inflight--;
      if (this.queue.length > 0) {
        setImmediate(() => this.processNext());
      }
    }
  }

  public clear(): void {
    this.queue = [];
    this.inflight = 0;
  }
}
