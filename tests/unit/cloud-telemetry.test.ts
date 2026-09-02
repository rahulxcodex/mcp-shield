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
});
