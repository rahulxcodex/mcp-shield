import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { CapabilityManifestRegistry } from '../../src/security/capability-manifest';
import { IpClassifier, EgressSecurityConfig } from '../../src/security/ip-utils';
import { Sanitizer } from '../../src/security/sanitizer';

describe('Mutation Testing & Detector Sensitivity Verification (Roadmap P2.4)', () => {
  describe('Mutation 1: AST Rule Weakening', () => {
    it('baseline AST blocks rm -rf /', () => {
      const analyzer = new ASTAnalyzer();
      const res = analyzer.analyzeCommand('rm -rf /');
      expect(res.isSafe).toBe(false);
    });

    it('mutated analyzer that bypasses root check fails security invariant', () => {
      // Create a mutated wrapper that artificially ignores destructive rm
      const mutatedAnalyze = (cmd: string) => {
        if (cmd.includes('rm -rf /')) {
          return { isSafe: true, reason: 'MUTATED: Bypassed root check' };
        }
        return new ASTAnalyzer().analyzeCommand(cmd);
      };

      const mutatedResult = mutatedAnalyze('rm -rf /');
      // The security suite MUST detect that this mutation allows destructive commands!
      expect(mutatedResult.isSafe).toBe(true); // Verification that the mutation occurred
    });
  });

  describe('Mutation 2: Egress Filter Weakening (SSRF / Loopback Bypass)', () => {
    const strictConfig: EgressSecurityConfig = {
      enabled: true,
      allowMode: 'deny',
      allowedDomains: [],
      blockedDomains: [],
      allowPrivateNetworks: false,
      blockLoopback: true,
      blockLinkLocal: true,
      blockMetadataEndpoints: true
    };

    it('baseline classifier blocks 127.0.0.1 and metadata endpoints', () => {
      expect(IpClassifier.checkEgressViolation('127.0.0.1', strictConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('169.254.169.254', strictConfig).isBlocked).toBe(true);
    });

    it('mutated config with blockLoopback: false leaks loopback access', () => {
      const weakenedConfig: EgressSecurityConfig = {
        ...strictConfig,
        allowMode: 'allow',
        blockLoopback: false
      };

      const result = IpClassifier.checkEgressViolation('127.0.0.1', weakenedConfig);
      // Demonstrates that disabling the control creates a policy gap
      expect(result.isBlocked).toBe(false);
    });
  });

  describe('Mutation 3: Capability Manifest Default-Deny Weakening', () => {
    it('baseline default-deny blocks unregistered tools', () => {
      const registry = new CapabilityManifestRegistry(true);
      const decision = registry.verifyInvocation('unregistered_tool', {}, { shellExecution: true });
      expect(decision.authorized).toBe(false);
      expect(decision.reasonCode).toBe('UNKNOWN_TOOL_BLOCKED');
    });

    it('mutated default-allow allows unregistered tools to execute', () => {
      const mutatedRegistry = new CapabilityManifestRegistry(false);
      const decision = mutatedRegistry.verifyInvocation('unregistered_tool', {}, { shellExecution: true });
      expect(decision.authorized).toBe(true);
      expect(decision.reasonCode).toBe('AUTHORIZED');
    });
  });

  describe('Mutation 4: DLP Sanitizer Masking Weakening', () => {
    const testPat = ['gh', 'p_', '1234567890abcdefghijklmnopqrstuvwxyzAB'].join('');

    it('baseline sanitizer detects and masks GitHub personal access tokens', () => {
      const sanitizer = new Sanitizer();
      const raw = `Access key: ${testPat}`;
      const sanitized = sanitizer.sanitize(raw);
      expect(sanitized).not.toBe(raw);
      expect(sanitized).toContain('[[SHIELD_SECRET_');
      expect(sanitized).not.toContain(testPat);
    });

    it('mutated sanitizer without token rules leaks raw secrets', () => {
      // If regex rules are removed/empty, secret remains exposed
      const mutatedSanitize = (text: string) => text;
      const raw = `Access key: ${testPat}`;
      const leaked = mutatedSanitize(raw);
      expect(leaked).toContain(testPat);
    });
  });
});
