import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { LicenseManager } from '../../src/security/license-manager';

describe('Cross-Repo Security Drift & Cryptographic License Hardening', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('Finding 1 & 4: Trial Machine Binding and Trust-Root Attestation', () => {
    it('generates a stable deterministic machine fingerprint', () => {
      const fp1 = LicenseManager.getMachineFingerprint();
      const fp2 = LicenseManager.getMachineFingerprint();
      expect(typeof fp1).toBe('string');
      expect(fp1.length).toBe(64); // SHA-256 hex
      expect(fp1).toBe(fp2);
    });

    it('enforces machine fingerprint binding on trial licenses', () => {
      const lm = new LicenseManager();
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

      process.env.MCP_SHIELD_PUBLIC_KEY = pubPem;
      process.env.MCP_SHIELD_ALLOW_UNVERIFIED_ROOT = 'true';

      const targetFingerprint = 'target-machine-fingerprint-01';
      const trialPayload = {
        githubId: 'developer-user',
        tier: 'enterprise-trial',
        isTrial: true,
        machineFingerprint: targetFingerprint,
        expiresAt: Date.now() + 1000 * 3600 * 24 * 30,
      };

      const payloadString = JSON.stringify(trialPayload);
      const b64Payload = Buffer.from(payloadString).toString('base64');
      const signature = crypto.sign(null, Buffer.from(payloadString), privPem);
      const validKey = `${b64Payload}.${signature.toString('base64')}`;

      // Verification succeeds when fingerprint matches
      const verified = lm.verifyLicense(validKey, { machineFingerprint: targetFingerprint });
      expect(verified).toBe(true);

      // Verification fails when fingerprint is different (e.g. shared on public forums)
      expect(() => {
        lm.verifyLicense(validKey, { machineFingerprint: 'foreign-machine-fingerprint-99' });
      }).toThrow(/License binding violation: Trial license is bound to a different machine\/environment/);
    });

    it('rejects untrusted MCP_SHIELD_PUBLIC_KEY override without vendor attestation', () => {
      const lm = new LicenseManager();
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

      process.env.MCP_SHIELD_PUBLIC_KEY = pubPem;
      process.env.MCP_SHIELD_STRICT_ATTESTATION = 'true';
      delete process.env.MCP_SHIELD_ALLOW_UNVERIFIED_ROOT;
      delete process.env.MCP_SHIELD_TRUST_ATTESTATION;

      expect(() => lm.verifyLicense('dummy.dummy')).toThrow(
        /Untrusted root override: Custom MCP_SHIELD_PUBLIC_KEY requires vendor attestation/
      );
    });
  });

  describe('Finding 10: Zero-Drift Security Parity Between Repos', () => {
    const cloudDashboardRoot = path.resolve(__dirname, '../../cloud-dashboard');
    const licensingRoot = path.resolve(__dirname, '../../../mcp-shield-licensing');

    const syncedSecurityFiles = [
      'src/lib/authz.ts',
      'src/lib/schema-integrity.ts',
      'src/lib/api-response.ts',
      'src/lib/distributed-state.ts',
      'src/lib/api-keys.ts',
      'src/app/api/v1/admin/break-glass/route.ts',
      'src/app/api/v1/organizations/[id]/transfer-owner/route.ts',
      'src/app/api/v1/policy/sync/route.ts',
      'src/app/api/v1/telemetry/ingest/route.ts',
      'src/app/api/license/route.ts',
    ];

    it.each(syncedSecurityFiles)('verifies exact parity for %s between cloud-dashboard and mcp-shield-licensing', (relPath) => {
      const cloudPath = path.join(cloudDashboardRoot, relPath);
      const licPath = path.join(licensingRoot, relPath);

      expect(fs.existsSync(cloudPath)).toBe(true);
      expect(fs.existsSync(licPath)).toBe(true);

      const cloudContent = fs.readFileSync(cloudPath, 'utf8').replace(/\r\n/g, '\n').trim();
      const licContent = fs.readFileSync(licPath, 'utf8').replace(/\r\n/g, '\n').trim();

      expect(cloudContent).toBe(licContent);
    });
  });
});
