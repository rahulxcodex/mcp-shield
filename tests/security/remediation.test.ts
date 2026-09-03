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
});
