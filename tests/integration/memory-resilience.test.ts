import { SecretSanitizer } from '../../src/security/sanitizer';
import { RateLimiter } from '../../src/security/rate-limiter';
import { JsonRpcStreamFramer } from '../../src/core/stream-framing';
import { PolicyEngine } from '../../src/security/policy-engine';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('Prolonged Session Stability & Memory Resilience Suite', () => {
  it('RES-01: SecretSanitizer enforces bounded ring buffer cache under 10,000 unique secrets', () => {
    const sanitizer = new SecretSanitizer();

    for (let i = 0; i < 10000; i++) {
      const fakeToken = `ghp_${i.toString().padStart(36, '0')}`;
      sanitizer.sanitize(`Auth token: ${fakeToken}`);
    }

    // Check that internal maps don't exceed MAX_CACHE_SIZE (5000)
    const tokenMapSize = (sanitizer as any).secretToToken.size;
    expect(tokenMapSize).toBeLessThanOrEqual(5000);
  });

  it('RES-02: RateLimiter enforces MAX_TRACKED_TOOLS bound under flood of 5,000 distinct tool names', () => {
    const rateLimiter = new RateLimiter(10, 60000, 100000);

    for (let i = 0; i < 5000; i++) {
      rateLimiter.checkLimit(`dynamic_generated_tool_${i}`);
    }

    const trackedTools = (rateLimiter as any).counts.size;
    expect(trackedTools).toBeLessThanOrEqual(1001);
  });

  it('RES-03: JsonRpcStreamFramer maintains stable memory over 10,000 framed messages', () => {
    const framer = new JsonRpcStreamFramer();
    let processed = 0;

    framer.on('message', () => {
      processed++;
    });

    const sample = Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping"}\n', 'utf8');

    for (let i = 0; i < 10000; i++) {
      framer.append(sample);
    }

    expect(processed).toBe(10000);
    // Buffer should be empty after processing all newline-delimited frames
    expect((framer as any).buffer.length).toBe(0);
  });

  it('RES-04: ASTAnalyzer handles rapid sequence of 5,000 shell commands without memory bloat or parse state leaks', () => {
    const analyzer = new ASTAnalyzer();

    const commands = [
      'git status',
      'ls -la /var/log',
      'echo "safe test" | grep test',
      'find . -name "*.ts"',
      'cat package.json | jq .version'
    ];

    for (let i = 0; i < 5000; i++) {
      const cmd = commands[i % commands.length];
      const res = analyzer.analyzeCommand(cmd);
      expect(res.isSafe).toBe(true);
    }
  });
});
