import { RequestDispatcher, ExecutionContext } from '../../src/core/dispatcher';

describe('Real Execution Cancellation (Roadmap Section 6)', () => {
  it('propagates AbortSignal and aborts active controller when cancel() is invoked', async () => {
    let wasAborted = false;
    let executionStarted = false;

    const handler = async (msg: any, ctx?: ExecutionContext) => {
      executionStarted = true;
      if (!ctx?.signal) return;

      return new Promise<void>((resolve) => {
        ctx.signal.addEventListener('abort', () => {
          wasAborted = true;
          resolve();
        });
        setTimeout(resolve, 500);
      });
    };

    const dispatcher = new RequestDispatcher(handler);
    dispatcher.enqueue({ jsonrpc: '2.0', id: 'req-cancel-test', method: 'test/execute' });

    // Allow event loop tick for message to start execution
    await new Promise(r => setTimeout(r, 20));
    expect(executionStarted).toBe(true);

    const cancelled = dispatcher.cancel('req-cancel-test');
    expect(cancelled).toBe(true);

    await new Promise(r => setTimeout(r, 20));
    expect(wasAborted).toBe(true);
  });

  it('aborts execution when notifications/cancelled is enqueued', async () => {
    let wasAborted = false;

    const handler = async (msg: any, ctx?: ExecutionContext) => {
      if (msg.method === 'test/long-run') {
        return new Promise<void>((resolve) => {
          ctx?.signal.addEventListener('abort', () => {
            wasAborted = true;
            resolve();
          });
          setTimeout(resolve, 500);
        });
      }
    };

    const dispatcher = new RequestDispatcher(handler);
    dispatcher.enqueue({ jsonrpc: '2.0', id: 42, method: 'test/long-run' });

    await new Promise(r => setTimeout(r, 20));

    dispatcher.enqueue({
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: { requestId: 42 }
    });

    await new Promise(r => setTimeout(r, 20));
    expect(wasAborted).toBe(true);
  });
});
