import { RequestDispatcher } from '../../src/core/dispatcher';

describe('RequestDispatcher Concurrency, Cancellation & Queue Recovery', () => {
  it('DISP-01: Proves 10-way concurrency limit and backpressure queuing', async () => {
    let activeWorkers = 0;
    let maxObservedActive = 0;
    const completed: number[] = [];

    const handler = async (msg: any) => {
      activeWorkers++;
      if (activeWorkers > maxObservedActive) {
        maxObservedActive = activeWorkers;
      }
      // Hold each request for 25ms to induce concurrent queue accumulation
      await new Promise((resolve) => setTimeout(resolve, 25));
      activeWorkers--;
      completed.push(msg.id);
    };

    const dispatcher = new RequestDispatcher(handler, undefined, {
      maxInflightRequests: 10,
      maxQueueDepth: 50,
      queueTimeoutMs: 5000
    });

    // Enqueue 25 valid JSON-RPC requests
    for (let i = 1; i <= 25; i++) {
      dispatcher.enqueue({ jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: `tool_${i}` } });
    }

    // Wait until all 25 have completed
    const startTime = Date.now();
    while (completed.length < 25 && Date.now() - startTime < 3000) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    expect(completed.length).toBe(25);
    expect(maxObservedActive).toBe(10); // Strictly constrained to maxInflightRequests (10)
    expect(dispatcher.getInflightCount()).toBe(0);
    expect(dispatcher.getQueueDepth()).toBe(0);
  });

  it('DISP-02: Cancels queued requests via cancel() and notifications/cancelled', async () => {
    const executed: number[] = [];
    const handler = async (msg: any) => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      executed.push(msg.id);
    };

    const dispatcher = new RequestDispatcher(handler, undefined, {
      maxInflightRequests: 2,
      maxQueueDepth: 20
    });

    // Enqueue requests: id 1 and 2 enter inflight immediately
    dispatcher.enqueue({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} });
    dispatcher.enqueue({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {} });

    // Requests 3 and 4 remain in queue
    dispatcher.enqueue({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: {} });
    dispatcher.enqueue({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {} });

    expect(dispatcher.getQueueDepth()).toBe(2);

    // Cancel queued request 3 explicitly
    const cancelled3 = dispatcher.cancel(3);
    expect(cancelled3).toBe(true);
    expect(dispatcher.getQueueDepth()).toBe(1);

    // Cancel queued request 4 via standard MCP notification
    dispatcher.enqueue({
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: { requestId: 4 }
    });
    expect(dispatcher.getQueueDepth()).toBe(0);

    // Wait for inflight to finish
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Request 1 and 2 ran, 3 and 4 were cleanly cancelled before execution
    expect(executed).toContain(1);
    expect(executed).toContain(2);
    expect(executed).not.toContain(3);
    expect(executed).not.toContain(4);
  });

  it('DISP-03: Recovers cleanly from queue backpressure without state leaks', async () => {
    let rejectedCount = 0;
    const errors: string[] = [];

    const errorHandler = (msg: any, code: number, errorMsg: string) => {
      rejectedCount++;
      errors.push(errorMsg);
    };

    const handler = async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    };

    const dispatcher = new RequestDispatcher(handler, errorHandler, {
      maxInflightRequests: 2,
      maxQueueDepth: 3
    });

    // Fill inflight (2) and queue (3)
    for (let i = 1; i <= 5; i++) {
      dispatcher.enqueue({ jsonrpc: '2.0', id: i, method: 'tools/call', params: {} });
    }

    // 6th and 7th requests exceed maxQueueDepth (3) -> backpressure rejection
    dispatcher.enqueue({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: {} });
    dispatcher.enqueue({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: {} });

    expect(rejectedCount).toBe(2);
    expect(errors[0]).toContain('Backpressure');

    // Wait for queue to drain
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Queue is now recovered, can accept new requests
    expect(dispatcher.getQueueDepth()).toBe(0);
    dispatcher.enqueue({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: {} });
    expect(dispatcher.getInflightCount()).toBeGreaterThan(0);

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(dispatcher.getInflightCount()).toBe(0);
  });
});
