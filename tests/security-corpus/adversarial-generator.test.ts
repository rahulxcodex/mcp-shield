import { AdversarialAttackGenerator, MutationFamily } from '../../src/security/adversarial/adversarial-generator';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { UnicodeNormalizer } from '../../src/security/unicode-normalizer';
import { PathSecurityResolver } from '../../src/security/path-resolver';
import { IpClassifier, EgressSecurityConfig } from '../../src/security/ip-utils';
import { Sanitizer } from '../../src/security/sanitizer';

describe('Roadmap Step 2 — Adversarial Attack Generator Pipeline', () => {
  const families: MutationFamily[] = [
    'URL_ENCODING',
    'DOUBLE_URL_ENCODING',
    'UNICODE_CONFUSABLES',
    'ZERO_WIDTH_CHARS',
    'QUOTE_MUTATION',
    'ESCAPE_MUTATION',
    'VARIABLE_EXPANSION',
    'BASE64_ENCODING',
    'NESTED_SHELL',
    'PIPELINE_MUTATION',
    'ARGUMENT_SPLITTING',
    'WHITESPACE_MUTATION',
    'CASE_MUTATION',
    'PATH_TRAVERSAL_MUTATION',
    'IP_REPRESENTATION_MUTATION'
  ];

  it('generates variants across all mutation families without crashing', () => {
    const baseCommand = 'rm -rf /etc/passwd';
    for (const fam of families) {
      const mutated = AdversarialAttackGenerator.mutatePayload(baseCommand, fam);
      expect(mutated).toBeDefined();
      expect(typeof mutated).toBe('string');
      expect(mutated.length).toBeGreaterThan(0);
    }
  });

  it('generates a full adversarial attack suite from seeds', () => {
    const suite = AdversarialAttackGenerator.generateAdversarialSuite(5);
    expect(suite.length).toBeGreaterThanOrEqual(5 * families.length);

    // Verify MCP request construction invariant
    for (const item of suite) {
      expect(item.mcpRequest.jsonrpc).toBe('2.0');
      expect(item.mcpRequest.method).toBeDefined();
      expect(item.mcpRequest.params).toBeDefined();
      expect(item.expectedDecision).toBeDefined();
    }
  });

  describe('Adversarial Invariant Hardening against Generated Variants', () => {
    it('catches Unicode confusable variations of curl / rm commands', () => {
      const mutated = AdversarialAttackGenerator.mutatePayload('curl http://evil.com', 'UNICODE_CONFUSABLES');
      // Normalize before inspection
      const normalized = UnicodeNormalizer.normalize(mutated);
      expect(normalized).toContain('curl');
      expect(normalized).toContain('http://evil.com');
    });

    it('catches path traversal mutations with embedded segments', () => {
      const mutated = AdversarialAttackGenerator.mutatePayload('cat /etc/passwd', 'PATH_TRAVERSAL_MUTATION');
      const resolved = PathSecurityResolver.resolveForPolicy(mutated.split(' ')[1]);
      expect(resolved.hasTraversalAttempt).toBe(true);
    });

    it('catches obfuscated IP representation mutations targeting loopback/metadata', () => {
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

      const mutatedIp = AdversarialAttackGenerator.mutatePayload('http://127.0.0.1/api', 'IP_REPRESENTATION_MUTATION');
      const violation = IpClassifier.checkEgressViolation(mutatedIp, strictConfig);
      expect(violation.isBlocked).toBe(true);
    });

    it('catches nested shell execution variants', () => {
      const mutated = AdversarialAttackGenerator.mutatePayload('rm -rf /', 'NESTED_SHELL');
      const analyzer = new ASTAnalyzer();
      const res = analyzer.analyzeCommand(mutated);
      expect(res.isSafe).toBe(false);
    });
  });
});
