import { SecurityIntelligenceEngine } from '../../src/security/intelligence-engine';
import { intelServiceCircuitBreaker } from '../../src/security/circuit-breaker';

describe('Chaos Engineering: Enterprise Intelligence Fallback & Degradation Invariants', () => {
  beforeEach(() => {
    intelServiceCircuitBreaker.reset();
    jest.restoreAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('CHAOS-001: Offline intel service falls back to local heuristics for low-risk action', async () => {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:59999'));

    const result = await SecurityIntelligenceEngine.evaluateViaRemoteIntel({
      toolName: 'read_readme',
      serverFingerprint: 'mock-server',
      astEntropy: 2.5,
      untrustedEgressRequested: false,
      apiKey: 'mcpshld_live_test_api_key_12345',
      endpointUrl: 'http://127.0.0.1:59999',
    });

    expect(result.source).toBe('LOCAL_FALLBACK');
    expect(result.riskScore).toBeDefined();
    expect(result.verdict).toBeDefined();
    expect(typeof result.riskScore).toBe('number');
  });

  test('CHAOS-002: Offline intel service fails closed (BLOCK) when high-risk egress is requested', async () => {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:59999'));

    const result = await SecurityIntelligenceEngine.evaluateViaRemoteIntel({
      toolName: 'execute_shell',
      serverFingerprint: 'mock-server',
      astEntropy: 5.0,
      untrustedEgressRequested: true,
      apiKey: 'mcpshld_live_test_api_key_12345',
      endpointUrl: 'http://127.0.0.1:59999',
    });

    expect(result.source).toBe('LOCAL_FALLBACK');
    expect(result.verdict).toBe('BLOCK');
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
    expect(result.reasoningVector).toContain('REMOTE_INTEL_UNAVAILABLE');
    expect(result.reasoningVector).toContain('HIGH_RISK_VECTOR_FAIL_CLOSED');
  });

  test('CHAOS-003: Offline intel service fails closed (BLOCK) when credential canary hits occur', async () => {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:59999'));

    const result = await SecurityIntelligenceEngine.evaluateViaRemoteIntel({
      toolName: 'fetch_user_token',
      serverFingerprint: 'mock-server',
      astEntropy: 3.0,
      untrustedEgressRequested: false,
      credentialCanaryHits: 1,
      apiKey: 'mcpshld_live_test_api_key_12345',
      endpointUrl: 'http://127.0.0.1:59999',
    });

    expect(result.source).toBe('LOCAL_FALLBACK');
    expect(result.verdict).toBe('BLOCK');
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
    expect(result.reasoningVector).toContain('HIGH_RISK_VECTOR_FAIL_CLOSED');
  });

  test('CHAOS-004: 503 Service Unavailable triggers graceful fallback', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({ error: 'Service Unavailable' }),
    } as any);

    const result = await SecurityIntelligenceEngine.evaluateViaRemoteIntel({
      toolName: 'list_files',
      serverFingerprint: 'mock-server',
      astEntropy: 2.0,
      untrustedEgressRequested: false,
      apiKey: 'mcpshld_live_test_api_key_12345',
      endpointUrl: 'http://127.0.0.1:59999',
    });

    expect(result.source).toBe('LOCAL_FALLBACK');
    expect(result.verdict).not.toBe('BLOCK');
  });

  test('CHAOS-005: Healthy remote intel service delivers authoritative remote verdict', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: 'success',
        data: {
          riskScore: 95,
          decision: 'BLOCK',
          reasonCodes: ['PROPRIETARY_THREAT_SIGNATURE_MATCH'],
          recommendedAction: 'Terminate agent session',
        },
      }),
    } as any);

    const result = await SecurityIntelligenceEngine.evaluateViaRemoteIntel({
      toolName: 'query_db',
      serverFingerprint: 'mock-server',
      astEntropy: 4.0,
      untrustedEgressRequested: false,
      apiKey: 'mcpshld_live_test_api_key_12345',
      endpointUrl: 'http://127.0.0.1:59999',
    });

    expect(result.source).toBe('REMOTE_ENTERPRISE_INTEL');
    expect(result.riskScore).toBe(95);
    expect(result.verdict).toBe('BLOCK');
    expect(result.reasoningVector).toContain('PROPRIETARY_THREAT_SIGNATURE_MATCH');
  });
});
