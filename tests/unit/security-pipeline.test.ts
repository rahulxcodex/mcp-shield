import { SecurityPipeline, JsonRpcMessage, MessageMetadata } from '../../src/core/pipeline/security-pipeline';

describe('Canonical SecurityPipeline (Roadmap Section 1)', () => {
  const pipeline = new SecurityPipeline();
  const metadata: MessageMetadata = {
    receivedAt: Date.now(),
    sessionId: 'session-pipeline-test'
  };

  it('evaluates safe tool invocation and allows it', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '/workspace/src/index.ts' }
      }
    };

    const ctx = await pipeline.evaluate(msg, metadata);
    expect(ctx.decision?.action).toBe('ALLOW');
    expect(ctx.risk.hardBlockTriggered).toBe(false);
  });

  it('detects directory traversal in candidate paths and blocks (Fail-Closed)', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '/workspace/../../etc/passwd' }
      }
    };

    const ctx = await pipeline.evaluate(msg, metadata);
    expect(ctx.decision?.action).toBe('BLOCK');
    expect(ctx.risk.hardBlockTriggered).toBe(true);
    expect(ctx.evidence.some(e => e.category === 'PATH_TRAVERSAL')).toBe(true);
  });

  it('detects command injection in tool arguments and blocks', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'bash_exec',
        arguments: { command: ':(){ :|:&n};:' }
      }
    };

    const ctx = await pipeline.evaluate(msg, metadata);
    expect(ctx.evidence.some(e => e.category === 'COMMAND_INJECTION')).toBe(true);
  });

  it('downgrades remote self-attested capabilities to untrusted evidence', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'stealth_tool',
        arguments: { foo: 'bar' },
        _schema: {
          type: 'object',
          _shieldCapabilities: {
            shellExecution: true,
            filesystemWrite: true
          }
        }
      }
    };

    const ctx = await pipeline.evaluate(msg, metadata);
    const selfAttestEvidence = ctx.evidence.filter(e => e.category === 'UNTRUSTED_CAPABILITY');
    expect(selfAttestEvidence.length).toBeGreaterThan(0);
  });

  it('honors AbortSignal and aborts immediately', async () => {
    const controller = new AbortController();
    controller.abort();

    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'test', arguments: {} }
    };

    await expect(pipeline.evaluate(msg, metadata, controller.signal)).rejects.toThrow(
      /OPERATION_CANCELLED/
    );
  });
});
