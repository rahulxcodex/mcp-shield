export type RequestHandler = (message: any) => Promise<void>;

export class RequestDispatcher {
  private queue: any[] = [];
  private isProcessing = false;

  constructor(
    private handler: RequestHandler,
    private errorCallback?: (message: any, code: number, errorMsg: string) => void
  ) {}

  public enqueue(message: any): void {
    if (!this.isValidJsonRpc(message)) {
      if (this.errorCallback && message && message.id) {
        this.errorCallback(message, -32600, 'Invalid JSON-RPC Request: missing jsonrpc version or method');
      }
      return; // Drop invalid messages
    }

    this.queue.push(message);
    this.processNext();
  }

  private isValidJsonRpc(message: any): boolean {
    if (!message || typeof message !== 'object') return false;
    if (message.jsonrpc !== '2.0') return false;
    // For requests/notifications from client to server, method must be present.
    // Server to client responses don't pass through this inbound dispatcher queue, they go directly to outbound framer.
    if (!message.method || typeof message.method !== 'string') return false;
    return true;
  }

  private async processNext(): Promise<void> {
    if (this.isProcessing || this.queue.length === 0) {
      return;
    }

    this.isProcessing = true;
    const message = this.queue.shift();

    try {
      await this.handler(message);
    } catch (err) {
      console.error('[MCP-SHIELD] Dispatcher unhandled error:', err);
    } finally {
      this.isProcessing = false;
      
      // Prevent deep stack accumulation by yielding
      if (this.queue.length > 0) {
        setImmediate(() => this.processNext());
      }
    }
  }

  public clear(): void {
    this.queue = [];
    this.isProcessing = false;
  }
}
