import * as fc from 'fast-check';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { PolicyEngine } from '../../src/security/policy-engine';

describe('Property-Based Tests', () => {
  describe('SecretSanitizer', () => {
    it('should be idempotent for any arbitrary string', () => {
      const sanitizer = new SecretSanitizer({ entropyThreshold: 4.5 });
      fc.assert(
        fc.property(fc.string({ maxLength: 1000 }), (payload) => {
          const pass1 = sanitizer.sanitize(payload);
          const pass2 = sanitizer.sanitize(pass1);
          return pass1 === pass2;
        }),
        { numRuns: 1000 }
      );
    });

    it('should always correctly restore to original payload when tokens are not altered', () => {
       const sanitizer = new SecretSanitizer({ entropyThreshold: 4.0 });
       fc.assert(
         fc.property(fc.string({ maxLength: 100 }), (payload) => {
           // Only test payloads that do not naturally contain the SHIELD_SECRET token signature 
           // and do not contain known patterns (which get tokenized). 
           // We are testing if restore(sanitize(payload)) == payload for arbitrary text,
           // OR if the restored string is at least equal to what we put in (if it had secrets).
           const tokenized = sanitizer.sanitize(payload);
           const restored = sanitizer.restore(tokenized);
           // If the payload had something recognized as a secret, restored will equal the original payload
           // (except if the original payload *already* had a token string by coincidence, but ignoring that edge case)
           if (!payload.includes('[[SHIELD_SECRET_')) {
              return restored === payload;
           }
           return true;
         }),
         { numRuns: 500 }
       );
    });
  });

  describe('PolicyEngine', () => {
    it('should never throw an exception during evaluate() regardless of input shape', () => {
      const engine = new PolicyEngine({
        version: '1.1',
        profile: 'test',
        redaction: { enabled: false, maskStyle: 'hash', highEntropyCheck: false, entropyThreshold: 5 },
        sandbox: { cowEnabled: false, cowStagingDir: 'test', autoCommitOnApproval: false },
        egress: { enabled: true, allowMode: 'allow', allowPrivateNetworks: true, blockLoopback: false, blockLinkLocal: false, blockMetadataEndpoints: false },
        rules: [],
        audit: { enabled: false, logDir: 'test', tamperEvidentHashing: false }
      });

      fc.assert(
        fc.property(
          fc.record({
            toolName: fc.string(),
            capabilities: fc.option(fc.array(fc.string()), { nil: undefined }),
            args: fc.dictionary(fc.string(), fc.anything()),
            evidence: fc.array(fc.record({ detector: fc.string(), finding: fc.string(), risk: fc.constantFrom('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') as fc.Arbitrary<'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'> }))
          }),
          (context) => {
            try {
              const result = engine.evaluate(context);
              return result && typeof result.decision === 'string';
            } catch (e) {
              return false; // Test fails if it throws
            }
          }
        ),
        { numRuns: 1000 }
      );
    });
  });
});
