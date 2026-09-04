import { SecretSanitizer } from '../../src/security/sanitizer';
import { RateLimiter } from '../../src/security/rate-limiter';
import { ProtocolValidator } from '../../src/core/protocol-validator';
import { SecurityPipeline } from '../../src/core/pipeline/security-pipeline';

jest.setTimeout(45000);

describe('Roadmap Step 2 — Prolonged Lifecycle & Memory Stress Testing', () => {
  it('enforces memory retention and bounded heap growth over 10,000 requests', async () => {
    // Force GC if available
    if (global.gc) {
      global.gc();
    }

    const initialMem = process.memoryUsage();
    const sanitizer = new SecretSanitizer();
    const rateLimiter = new RateLimiter(100, 60000, 5000);
    const validator = new ProtocolValidator();
    const pipeline = new SecurityPipeline();

    const samplePayload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'execute_command',
        arguments: {
          command: 'ls -la /tmp',
          secret: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12'
        }
      }
    };

    // Run 10,000 cycles
    for (let i = 0; i < 10000; i++) {
      validator.validateInbound(samplePayload);
      sanitizer.sanitize(`Output ${i}: ghp_1234567890abcdefghijklmnopqrstuvwxyz12`);
      rateLimiter.checkLimit(`tool_${i % 100}`);

      if (i % 500 === 0) {
        await pipeline.evaluate(samplePayload as any, {
          receivedAt: Date.now(),
          sessionId: `sess-${i % 10}`
        });
      }
    }

    if (global.gc) {
      global.gc();
    }

    const finalMem = process.memoryUsage();
    const heapGrowthBytes = Math.max(0, finalMem.heapUsed - initialMem.heapUsed);
    const heapGrowthMB = heapGrowthBytes / (1024 * 1024);

    // Explicit retention limit: heap growth must be strictly under 35 MB after 10,000 cycles
    expect(heapGrowthMB).toBeLessThan(35);

    // Vault and rate limiter internal collections must strictly adhere to maximum bounds
    const vaultSize = (sanitizer as any).vault.secrets.size;
    expect(vaultSize).toBeLessThanOrEqual(5000);
  });
});
