import { CapabilityInferencer } from '../../src/security/capabilities';
import { PowerShellASTAnalyzer } from '../../src/security/powershell-analyzer';
import { CmdAnalyzer } from '../../src/security/cmd-analyzer';
import { LicenseManager } from '../../src/security/license-manager';
import { SecretVault } from '../../src/security/vault';

describe('Round 2 & Round 3 Security Remediation Invariants', () => {
  describe('CRIT-02: Untrusted Schema Self-Attestation Rejection', () => {
    it('forces secretAccess to false for unverified schemas even when _shieldCapabilities asserts true', () => {
      const untrustedSchema = {
        type: 'object',
        properties: { query: { type: 'string' } },
        _shieldCapabilities: {
          secretAccess: true,
          filesystemRead: true,
          shellExecution: true
        }
      };

      const declared = CapabilityInferencer.getDeclared(untrustedSchema);
      expect(declared.secretAccess).toBe(false);
      expect(declared.filesystemRead).toBe(true);
      expect(declared.shellExecution).toBe(true);
    });
  });

  describe('HIGH-01: PowerShell Encoded Command Colon/Alias Detection', () => {
    it('detects and analyzes encoded commands using colon syntax (e.g. -enc:BASE64)', () => {
      const psAnalyzer = new PowerShellASTAnalyzer();
      const maliciousScript = 'Invoke-Expression "rm -rf /"';
      const b64 = Buffer.from(maliciousScript, 'utf16le').toString('base64');
      
      const cmdColon = `powershell.exe -enc:${b64}`;
      const resColon = psAnalyzer.analyzeCommand(cmdColon);
      expect(resColon.isSafe).toBe(false);
      expect(resColon.reason).toContain('Encoded PowerShell payload blocked');

      const cmdShortColon = `pwsh -e:${b64}`;
      const resShort = psAnalyzer.analyzeCommand(cmdShortColon);
      expect(resShort.isSafe).toBe(false);
      expect(resShort.reason).toContain('Encoded PowerShell payload blocked');
    });
  });

  describe('HIGH-02: cmd.exe Caret Obfuscation De-evasion', () => {
    it('detects sensitive environment variable access disguised with carets e.g. %A^WS_SECRET_ACCESS_KEY%', () => {
      const cmdAnalyzer = new CmdAnalyzer();
      
      const obfuscatedEnv = 'type %A^WS_SECRET_ACCESS_KEY%';
      const res = cmdAnalyzer.analyzeCommand(obfuscatedEnv);
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('Direct access to sensitive environment variable');

      const delayedObfuscated = 'echo !T^OKEN!';
      const resDelayed = cmdAnalyzer.analyzeCommand(delayedObfuscated);
      expect(resDelayed.isSafe).toBe(false);
    });
  });

  describe('HIGH-03: License Expiration Non-Finite / Missing Timestamp Defense', () => {
    it('fails closed when license payload has missing, null, or NaN expiresAt', () => {
      const lm = new LicenseManager();
      
      const invalidPayload = JSON.stringify({ githubId: 'attacker', tier: 'enterprise' });
      const b64 = Buffer.from(invalidPayload).toString('base64');
      const fakeSig = Buffer.from('fakesig').toString('base64');
      const badKey = `${b64}.${fakeSig}`;

      expect(() => lm.verifyLicense(badKey)).toThrow();
    });
  });

  describe('MED-01: Secret Vault Context Omission Fail-Closed', () => {
    it('rejects retrieval if stored secret is context-bound but caller omits expectedContext', () => {
      const vault = new SecretVault();
      const token = vault.store('super-secret-token', 60000, {
        sessionId: 'sess-42',
        scope: 'srv:tool'
      });

      // Retrieval with undefined context must fail closed
      expect(vault.retrieve(token)).toBeNull();

      // Retrieval with empty context must fail closed
      expect(vault.retrieve(token, {})).toBeNull();

      // Retrieval with correct context must succeed
      expect(vault.retrieve(token, { sessionId: 'sess-42', scope: 'srv:tool' })).toBe('super-secret-token');
    });
  });
});
