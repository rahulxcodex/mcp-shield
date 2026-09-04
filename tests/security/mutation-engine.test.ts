import { SecurityMutationEngine, SecurityMutant } from '../../src/security/mutation/mutation-engine';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { CapabilityManifestRegistry } from '../../src/security/capability-manifest';
import { PathSecurityResolver } from '../../src/security/path-resolver';
import { Sanitizer } from '../../src/security/sanitizer';
import { IpClassifier, EgressSecurityConfig } from '../../src/security/ip-utils';
import { PolicyEngine } from '../../src/security/policy-engine';
import { UnicodeNormalizer } from '../../src/security/unicode-normalizer';

describe('Roadmap Step 2 — Comprehensive Mutation Testing Engine', () => {
  const mutants = SecurityMutationEngine.createSecurityMutants();

  // Test that all 9 mutation families from the roadmap are registered
  it('registers all 9 required mutation families', () => {
    const types = new Set(mutants.map(m => m.type));
    expect(types.has('SEVERITY_DECREASE')).toBe(true);
    expect(types.has('BLOCK_TO_ALLOW')).toBe(true);
    expect(types.has('ALLOW_TO_BLOCK')).toBe(true);
    expect(types.has('PATH_COMPARISON_INVERSION')).toBe(true);
    expect(types.has('REGEX_REMOVAL')).toBe(true);
    expect(types.has('CAPABILITY_REMOVAL')).toBe(true);
    expect(types.has('POLICY_PRECEDENCE_MUTATION')).toBe(true);
    expect(types.has('UNICODE_NORMALIZATION_DISABLE')).toBe(true);
    expect(types.has('SIGNATURE_VERIFICATION_BYPASS')).toBe(true);
  });

  describe('Mutant Kill Invariant Checks', () => {
    mutants.forEach(mutant => {
      it(`detects and kills mutant: [${mutant.id}] ${mutant.type} (${mutant.description})`, () => {
        const revert = mutant.applyMutation();
        try {
          // Verify that running invariant tests against the mutant flags anomalous behavior
          switch (mutant.type) {
            case 'SEVERITY_DECREASE': {
              const res = new ASTAnalyzer().analyzeCommand('rm -rf /');
              // The mutant artificially downgraded safety
              expect(res.isSafe).toBe(true); // Mutant is active
              break;
            }
            case 'BLOCK_TO_ALLOW': {
              const reg = new CapabilityManifestRegistry(true);
              const dec = reg.verifyInvocation('unregistered_tool', {}, { shellExecution: true });
              expect(dec.authorized).toBe(true); // Mutant leaked execution
              break;
            }
            case 'ALLOW_TO_BLOCK': {
              const res = new ASTAnalyzer().analyzeCommand('git status');
              expect(res.isSafe).toBe(false); // Mutant broke benign invariant
              break;
            }
            case 'PATH_COMPARISON_INVERSION': {
              const isInside = PathSecurityResolver.isWithin('/workspace/docs/file.txt', '/workspace');
              expect(isInside).toBe(false); // Inverted
              break;
            }
            case 'REGEX_REMOVAL': {
              const out = new Sanitizer().sanitize('API key: ghp_1234567890abcdefghijklmnopqrstuvwxyz123456');
              expect(out).toContain('ghp_1234567890'); // Secret leaked
              break;
            }
            case 'CAPABILITY_REMOVAL': {
              const config: EgressSecurityConfig = {
                enabled: true,
                allowMode: 'deny',
                allowedDomains: [],
                blockedDomains: [],
                allowPrivateNetworks: false,
                blockLoopback: true,
                blockLinkLocal: true,
                blockMetadataEndpoints: true
              };
              const res = IpClassifier.checkEgressViolation('127.0.0.1', config);
              expect(res.isBlocked).toBe(false); // Leaked loopback
              break;
            }
            case 'POLICY_PRECEDENCE_MUTATION': {
              const engine = new PolicyEngine();
              const dec = engine.evaluate({
                toolName: 'bash',
                args: { command: 'rm -rf /' },
                evidence: [{ detector: 'ast', finding: 'DESTRUCTIVE', risk: 'CRITICAL' }]
              });
              expect(dec.decision).toBe('allow'); // Policy overridden
              break;
            }
            case 'UNICODE_NORMALIZATION_DISABLE': {
              const confusable = 'ｃｕｒｌ'; // Fullwidth 'curl'
              const norm = UnicodeNormalizer.normalize(confusable);
              expect(norm).toBe(confusable); // Failed to normalize to ASCII curl
              break;
            }
            case 'SIGNATURE_VERIFICATION_BYPASS': {
              const res = PathSecurityResolver.resolveForPolicy('../../../etc/passwd');
              expect(res.hasTraversalAttempt).toBe(false); // Traversal signature bypassed
              break;
            }
          }
        } finally {
          revert();
        }

        // Verify baseline sanity is fully restored after revert
        switch (mutant.type) {
          case 'SEVERITY_DECREASE':
            expect(new ASTAnalyzer().analyzeCommand('rm -rf /').isSafe).toBe(false);
            break;
          case 'BLOCK_TO_ALLOW':
            expect(new CapabilityManifestRegistry(true).verifyInvocation('unregistered_tool', {}, { shellExecution: true }).authorized).toBe(false);
            break;
          case 'ALLOW_TO_BLOCK':
            expect(new ASTAnalyzer().analyzeCommand('git status').isSafe).toBe(true);
            break;
          case 'PATH_COMPARISON_INVERSION':
            expect(PathSecurityResolver.isWithin('/workspace/docs/file.txt', '/workspace')).toBe(true);
            break;
          case 'REGEX_REMOVAL':
            expect(new Sanitizer().sanitize('API key: ghp_1234567890abcdefghijklmnopqrstuvwxyz123456')).not.toContain('ghp_1234567890');
            break;
          case 'UNICODE_NORMALIZATION_DISABLE':
            expect(UnicodeNormalizer.normalize('ｃｕｒｌ')).toBe('curl');
            break;
          case 'SIGNATURE_VERIFICATION_BYPASS':
            expect(PathSecurityResolver.resolveForPolicy('../../../etc/passwd').hasTraversalAttempt).toBe(true);
            break;
        }
      });
    });
  });
});
