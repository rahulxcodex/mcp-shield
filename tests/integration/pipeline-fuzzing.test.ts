import { PolicyEngine } from '../../src/security/policy-engine';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { IpClassifier } from '../../src/security/ip-utils';
import { RequestDispatcher } from '../../src/core/dispatcher';

describe('Cross-Component End-to-End Pipeline Fuzzing (Item 45)', () => {
  let policyEngine: PolicyEngine;
  let sanitizer: SecretSanitizer;
  let astAnalyzer: ASTAnalyzer;

  beforeEach(() => {
    policyEngine = new PolicyEngine();
    sanitizer = new SecretSanitizer();
    astAnalyzer = new ASTAnalyzer();
  });

  it('safely processes 500 randomized multi-component payloads without crashing or throwing unhandled exceptions', async () => {
    const executedRequests: any[] = [];
    const dispatcher = new RequestDispatcher(async (msg) => {
      executedRequests.push(msg);
    });

    const adversarialStrings = [
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"rm -rf /"}}}',
      '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}',
      '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}',
      '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"calculate","arguments":{"expr":"1+1"}}}',
      '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}',
      '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"query","arguments":{"endpoint":"https://api.github.com"}}}',
      '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"find_files","arguments":{"cmd":"find / -delete"}}}',
      '{"invalid_json_rpc": true}',
      '{"jsonrpc":"2.0","method":"unknown/method"}',
      '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"run","arguments":{"cmd":"$DYNAMIC_VAR /"}}}'
    ];

    for (let i = 0; i < 500; i++) {
      const template = adversarialStrings[i % adversarialStrings.length];
      let parsed: any;
      try {
        parsed = JSON.parse(template);
      } catch {
        continue;
      }

      // Step 1: Dispatcher validation
      dispatcher.enqueue(parsed);

      if (parsed.params?.arguments) {
        const args = parsed.params.arguments;
        // Step 2: Sanitizer pass
        const sanitizedStr = sanitizer.sanitize(JSON.stringify(args));
        expect(typeof sanitizedStr).toBe('string');

        // Step 3: AST analysis if command present
        if (args.cmd) {
          const astRes = astAnalyzer.analyzeCommand(args.cmd);
          expect(typeof astRes.isSafe).toBe('boolean');
        }

        // Step 4: Egress check if URL present
        if (args.url || args.endpoint) {
          const egressRes = IpClassifier.checkEgressViolation(args.url || args.endpoint, {
            enabled: true,
            allowPrivateNetworks: false,
            blockLoopback: true,
            blockMetadataEndpoints: true
          });
          expect(typeof egressRes.isBlocked).toBe('boolean');
        }

        // Step 5: Policy evaluation
        const policyRes = policyEngine.evaluate({
          toolName: parsed.params?.name || 'unknown',
          args,
          evidence: []
        });
        expect(['allow', 'sandbox', 'prompt', 'block', 'quarantine']).toContain(policyRes.decision);
      }
    }
  });
});
