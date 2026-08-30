export type RequestHandler = (message: any) => Promise<void>;

export class RequestDispatcher {
  private queue: any[] = [];
  private isProcessing = false;

  constructor(private handler: RequestHandler) {}

  public enqueue(message: any): void {
    // Notifications and non-requests can bypass or be handled lightly, 
    // but for ordered execution, we just queue everything from host to server.
    this.queue.push(message);
    this.processNext();
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
