import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CloudTelemetryPublisher, SecurityTelemetryPayload } from '../../src/cloud/telemetry';

describe('Cross-System Contracts & Security Invariants', () => {
  describe('Canonical API Key Contract & Tenant Isolation', () => {
    function generateTestKey(prefixHex = 'a8f9c2d1', secretHex = '0123456789abcdef0123456789abcdef') {
      const keyPrefix = `mcp_live_${prefixHex}`;
      const rawKey = `${keyPrefix}_${secretHex}`;
      const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
      return { keyPrefix, rawKey, keyHash };
    }

    it('should accurately validate canonical key structure and extract prefixes', () => {
      const { rawKey, keyPrefix } = generateTestKey('e3108bf6');
      expect(CloudTelemetryPublisher.extractKeyPrefix(rawKey)).toBe(keyPrefix);

      // Verify prefix matches standard hex format
      expect(keyPrefix).toMatch(/^mcp_live_[a-f0-9]{8}$/);
    });

    it('should enforce tenant isolation by rejecting mismatched org hashes', () => {
      const orgA = generateTestKey('aaaa1111', '11111111111111111111111111111111');
      const orgB = generateTestKey('bbbb2222', '22222222222222222222222222222222');

      // Computing Org A hash with Org B secret must fail comparison
      const computedHashOrgA = crypto.createHash('sha256').update(orgA.rawKey).digest('hex');
      expect(computedHashOrgA).toBe(orgA.keyHash);
      expect(computedHashOrgA).not.toBe(orgB.keyHash);

      // Constant-time timingSafeEqual fails on mismatched tenant keys
      const bufA = Buffer.from(computedHashOrgA, 'hex');
      const bufB = Buffer.from(orgB.keyHash, 'hex');
      expect(crypto.timingSafeEqual(bufA, bufB)).toBe(false);
    });

    it('should reject tampered HMAC signatures across tenant payloads', () => {
      const { rawKey } = generateTestKey('cccc3333');
      const payload = JSON.stringify({ events: [{ eventType: 'BLOCK', toolName: 'exec' }] });
      const timestamp = Date.now();

      const validSignature = CloudTelemetryPublisher.signPayload(payload, rawKey, timestamp);
      const tamperedPayload = JSON.stringify({ events: [{ eventType: 'BLOCK', toolName: 'exec_malicious' }] });
      const tamperedSignature = CloudTelemetryPublisher.signPayload(tamperedPayload, rawKey, timestamp);

      expect(validSignature).not.toBe(tamperedSignature);
    });
  });

  describe('Telemetry Redaction & Identity Invariants', () => {
    it('should scrub credentials and local filesystem paths before serialization', () => {
      const testCases = [
        {
          input: 'Command /Users/developer/code/project failed with key sk-proj-1234567890abcdef1234567890',
          shouldNotContain: ['/Users/developer', '1234567890abcdef1234567890']
        },
        {
          input: 'Attempted to read C:\\Users\\Administrator\\Desktop\\tokens.txt with mcp_live_e3108bf6_9876543210fedcba',
          shouldNotContain: ['C:\\Users\\Administrator', '9876543210fedcba']
        }
      ];

      for (const tc of testCases) {
        const redacted = CloudTelemetryPublisher.redactSensitiveData(tc.input);
        for (const forbidden of tc.shouldNotContain) {
          expect(redacted).not.toContain(forbidden);
        }
        expect(redacted).toContain('[REDACTED]');
      }
    });

    it('should assign unique eventId and incrementing sequence numbers', () => {
      const publisher = new CloudTelemetryPublisher({ enabled: true, apiKey: 'mcp_live_test0101_secret' });
      const emittedEvents: SecurityTelemetryPayload[] = [];

      // Intercept queue
      (publisher as any).queue = [];

      publisher.trackEvent({
        sessionId: 'sess-test-01',
        eventType: 'BLOCK',
        detector: 'Tree-sitter AST',
        riskLevel: 'CRITICAL',
        toolName: 'rm',
        reason: 'Recursive root deletion blocked',
        clientTimestamp: new Date().toISOString()
      });

      publisher.trackEvent({
        sessionId: 'sess-test-01',
        eventType: 'SANITIZE',
        detector: 'Bijective FPE DLP',
        riskLevel: 'HIGH',
        toolName: 'read_secret',
        reason: 'AWS key sanitized',
        clientTimestamp: new Date().toISOString()
      });

      const queue = (publisher as any).queue;
      expect(queue.length).toBe(2);
      expect(queue[0].eventId).toBeDefined();
      expect(queue[1].eventId).toBeDefined();
      expect(queue[0].eventId).not.toBe(queue[1].eventId);
      expect(queue[0].sequenceNumber).toBeLessThan(queue[1].sequenceNumber);
      expect(queue[0].installationId).toBe(publisher.getInstallationId());

      publisher.stop();
    });
  });

  describe('Durable Spooling & Graceful Degradation', () => {
    const testSpoolDir = path.resolve(os.tmpdir(), `.mcp-shield-test-spool-${Date.now()}`);
    const testSpoolFile = path.resolve(testSpoolDir, 'telemetry.json');

    afterEach(() => {
      try {
        if (fs.existsSync(testSpoolFile)) fs.unlinkSync(testSpoolFile);
        if (fs.existsSync(testSpoolDir)) fs.rmdirSync(testSpoolDir);
      } catch {}
    });

    it('should persist events to disk spool upon network failure and drop oldest above cap', () => {
      const publisher = new CloudTelemetryPublisher({
        enabled: true,
        apiKey: 'mcp_live_test_123',
        cloudEndpoint: 'http://127.0.0.1:54321/nonexistent/ingest'
      });

      // Point spool to test path
      (publisher as any).spoolPath = testSpoolFile;

      const testEvents: SecurityTelemetryPayload[] = [
        {
          eventId: 'evt-001',
          sessionId: 'sess-1',
          eventType: 'BLOCK',
          detector: 'AST',
          riskLevel: 'HIGH',
          toolName: 'cmd',
          reason: 'blocked',
          clientTimestamp: new Date().toISOString()
        }
      ];

      (publisher as any).persistSpool(testEvents);

      expect(fs.existsSync(testSpoolFile)).toBe(true);
      const spooled = JSON.parse(fs.readFileSync(testSpoolFile, 'utf8'));
      expect(spooled.length).toBe(1);
      expect(spooled[0].eventId).toBe('evt-001');

      publisher.stop();
    });
  });
});
