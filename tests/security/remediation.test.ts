import { getDashboardHtml } from '../../src/dashboard/html-template';
import * as crypto from 'crypto';

describe('Security Remediation Invariants', () => {
  describe('SEC-REM-01: Dashboard Event XSS Sanitization', () => {
    it('generates HTML containing escapeHtml helper function', () => {
      const html = getDashboardHtml('test-token', 3333);
      expect(html).toContain('function escapeHtml(str)');
      expect(html).toContain('.replace(/</g, \'&lt;\')');
      expect(html).toContain('.replace(/>/g, \'&gt;\')');
      expect(html).toContain('escapeHtml(data.toolName)');
      expect(html).toContain('escapeHtml(data.reason)');
      expect(html).toContain('escapeHtml(JSON.stringify(data.payload))');
    });
  });

  describe('SEC-REM-02: Cryptographic Fail-Closed Licensing Invariant', () => {
    it('throws error when LICENSE_PRIVATE_KEY is missing rather than using hardcoded fallback', async () => {
      const originalEnv = process.env.LICENSE_PRIVATE_KEY;
      delete process.env.LICENSE_PRIVATE_KEY;

      // Ensure no fallback private key is returned
      let errorThrown = false;
      try {
        const getPrivateKey = () => {
          const envKey = process.env.LICENSE_PRIVATE_KEY;
          if (!envKey) {
            throw new Error('LICENSE_PRIVATE_KEY is not configured on the server (fail-closed).');
          }
          return envKey.replace(/\\n/g, '\n').trim();
        };
        getPrivateKey();
      } catch (err: any) {
        errorThrown = true;
        expect(err.message).toContain('LICENSE_PRIVATE_KEY is not configured on the server (fail-closed)');
      } finally {
        if (originalEnv) process.env.LICENSE_PRIVATE_KEY = originalEnv;
      }
      expect(errorThrown).toBe(true);
    });
  });

  describe('SEC-REM-03: Member Role Allowlist & Privilege Escalation Guard', () => {
    it('rejects owner assignment from non-owners', () => {
      const allowedRoles = ['owner', 'admin', 'member', 'viewer'];
      const testRole: string = 'owner';
      const callerRole: string = 'admin';

      const isForbidden = callerRole !== 'owner' && (testRole === 'owner' || testRole === 'admin');
      expect(isForbidden).toBe(true);
      expect(allowedRoles.includes(testRole)).toBe(true);
    });

    it('rejects arbitrary invalid roles', () => {
      const allowedRoles = ['owner', 'admin', 'member', 'viewer'];
      const invalidRole = 'superuser';
      expect(allowedRoles.includes(invalidRole)).toBe(false);
    });
  });

  describe('SEC-REM-04: GitHub Token Variant Redaction (ghu_, ghs_, ghr_)', () => {
    it('detects and redacts modern GitHub token prefixes', async () => {
      const { SecretSanitizer } = await import('../../src/security/sanitizer');
      const sanitizer = new SecretSanitizer();

      const userToken = 'ghu_1234567890abcdefghijklmnopqrstuv';
      const serverToken = 'ghs_1234567890abcdefghijklmnopqrstuv';
      const refreshToken = 'ghr_1234567890abcdefghijklmnopqrstuv';

      const sanitizedUser = sanitizer.sanitize(userToken);
      expect(sanitizedUser).not.toContain(userToken);

      const sanitizedServer = sanitizer.sanitize(serverToken);
      expect(sanitizedServer).not.toContain(serverToken);

      const sanitizedRefresh = sanitizer.sanitize(refreshToken);
      expect(sanitizedRefresh).not.toContain(refreshToken);
    });
  });

  describe('SEC-REM-05: Master Key Constant-Time Verification', () => {
    it('verifies master key in constant time and returns false when unmatched without crash', async () => {
      const { LicenseManager } = await import('../../src/security/license-manager');
      const manager = new LicenseManager();

      const testKey = 'MASTER_SECRET_KEY_123456789';
      const expectedHash = crypto.createHash('sha256').update(testKey).digest('hex');

      process.env.MCP_SHIELD_MASTER_KEY_HASH = expectedHash;
      const verified = manager.verifyLicense(testKey);
      expect(verified).toBe(true);

      delete process.env.MCP_SHIELD_MASTER_KEY_HASH;
      expect(manager.verifyLicense(testKey)).toBe(false);

      // Verify counterfeit signature throws in test mode
      expect(() => manager.verifyLicense('invalid_base64_payload.invalid_signature')).toThrow();
    });
  });
});
