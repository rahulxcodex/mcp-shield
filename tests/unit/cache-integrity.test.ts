import { SecurityIntelligenceEngine } from '../../src/security/intelligence-engine';
import { CapabilityManifestRegistry, ToolCapabilityManifest } from '../../src/security/capability-manifest';
import { CircuitBreaker } from '../../src/security/circuit-breaker';

describe('Phase 15 — Caching & Consistency Integrity Suite', () => {
  let manifestRegistry: CapabilityManifestRegistry;
  let circuitBreaker: CircuitBreaker;

  beforeEach(() => {
    manifestRegistry = new CapabilityManifestRegistry(true);
    circuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 50,
      halfOpenMaxProbes: 2,
    });
  });

  it('CACHE-001: Enforces deterministic risk scoring and capability attestation', () => {
    const manifest: ToolCapabilityManifest = {
      toolName: 'read_secure_data',
      version: '1.0.0',
      allowedCapabilities: {
        filesystemRead: true,
      },
      allowedPaths: ['/safe/**'],
      schemaFingerprint: 'hash_abc123',
    };

    manifestRegistry.registerManifest(manifest);

    // Attest matching schema -> fingerprint generated
    const attestation1 = manifestRegistry.attestSchema('read_secure_data', { type: 'object' });
    expect(attestation1.fingerprint).toBeDefined();

    // Verification determinism
    const eval1 = SecurityIntelligenceEngine.calculateRiskScore({
      serverId: 'server-1',
      toolName: 'read_secure_data',
      actionType: 'fs:read',
    });
    const eval2 = SecurityIntelligenceEngine.calculateRiskScore({
      serverId: 'server-1',
      toolName: 'read_secure_data',
      actionType: 'fs:read',
    });
    expect(eval1.compositeScore).toBe(eval2.compositeScore);
  });

  it('CACHE-002: Immediately flags schema drift upon manifest change', () => {
    manifestRegistry.registerManifest({
      toolName: 'api_tool',
      version: '1.0.0',
      allowedCapabilities: {
        networkAccess: true,
      },
      allowedEgressDomains: ['api.example.com'],
      schemaFingerprint: 'original_fingerprint_123',
    });

    // Attest modified schema
    const driftResult = manifestRegistry.attestSchema('api_tool', {
      properties: { maliciousPayload: { type: 'string' } },
    });
    expect(driftResult.driftDetected).toBe(true);
  });

  it('CACHE-003: Circuit breaker state cache resets cleanly after timeout', async () => {
    expect(circuitBreaker.getState()).toBe('CLOSED');

    // Trigger 3 failures to trip circuit breaker into OPEN state
    for (let i = 0; i < 3; i++) {
      try {
        await circuitBreaker.execute(
          async () => {
            throw new Error('Remote failure');
          },
          (err) => {
            throw err;
          }
        );
      } catch {}
    }

    expect(circuitBreaker.getState()).toBe('OPEN');

    // Wait for reset timeout (50ms)
    await new Promise((resolve) => setTimeout(resolve, 60));

    // Next access transitions to HALF_OPEN
    expect(circuitBreaker.getState()).toBe('HALF_OPEN');

    // Successful probe closes circuit
    await circuitBreaker.execute(
      async () => 'success_result',
      () => 'fallback'
    );
    await circuitBreaker.execute(
      async () => 'success_result_2',
      () => 'fallback'
    );

    expect(circuitBreaker.getState()).toBe('CLOSED');
  });
});
