import { CloudTelemetryPublisher } from '../../src/cloud/telemetry';

describe('CloudTelemetryPublisher', () => {
  it('should generate valid HMAC-SHA256 signatures for telemetry packets', () => {
    const payload = JSON.stringify({ event: 'BLOCK', tool: 'execute_cmd' });
    const apiKey = 'mcp_live_secret_key_12345';
    const timestamp = 1788286000000;

    const signature = CloudTelemetryPublisher.signPayload(payload, apiKey, timestamp);
    expect(signature).toBeDefined();
    expect(signature.length).toBe(64); // SHA-256 hex string

    // Re-computing signature with same inputs yields identical hash
    const verifySig = CloudTelemetryPublisher.signPayload(payload, apiKey, timestamp);
    expect(verifySig).toBe(signature);
  });

  it('should queue events and flush cleanly when disabled without error', async () => {
    const publisher = new CloudTelemetryPublisher({ enabled: false });
    publisher.trackEvent({
      sessionId: 'test-session-1',
      eventType: 'BLOCK',
      detector: 'ast-analyzer',
      riskLevel: 'CRITICAL',
      toolName: 'execute_cmd',
      reason: 'Root deletion blocked',
      clientTimestamp: new Date().toISOString()
    });

    const result = await publisher.flush();
    expect(result).toBe(true);
    publisher.stop();
  });

  it('should extract canonical key prefix accurately across formats', () => {
    const canonicalKey = 'mcp_live_a1b2c3d4_0123456789abcdef0123456789abcdef';
    expect(CloudTelemetryPublisher.extractKeyPrefix(canonicalKey)).toBe('mcp_live_a1b2c3d4');

    const secKey = 'mcp_live_sec_11223344_0123456789abcdef0123456789abcdef';
    expect(CloudTelemetryPublisher.extractKeyPrefix(secKey)).toBe('mcp_live_sec_11223344');

    expect(CloudTelemetryPublisher.extractKeyPrefix('mcp_live_a1b2c3d4')).toBe('mcp_live_a1b2c3d4');
  });

  it('should redact sensitive tokens and absolute paths before serialization', () => {
    const rawReason = 'Failed authentication with mcp_live_a1b2c3d4_0123456789abcdef and path /Users/admin/secrets.env';
    const redacted = CloudTelemetryPublisher.redactSensitiveData(rawReason);
    expect(redacted).not.toContain('0123456789abcdef');
    expect(redacted).toContain('[REDACTED]');
    expect(redacted).not.toContain('/Users/admin');
    expect(redacted).toContain('<USER_DIR>');
  });

  it('should maintain stable installation id and assign sequence numbers', () => {
    const publisher = new CloudTelemetryPublisher({ enabled: true, apiKey: 'mcp_live_test_key_123' });
    expect(publisher.getInstallationId()).toBeDefined();
    expect(publisher.getInstallationId()).toMatch(/^inst_/);
    publisher.stop();
  });
});

