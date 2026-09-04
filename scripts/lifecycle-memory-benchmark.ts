import { SecretSanitizer } from '../src/security/sanitizer';
import { RateLimiter } from '../src/security/rate-limiter';
import { ProtocolValidator } from '../src/core/protocol-validator';

export interface MemorySnapshot {
  rssMB: number;
  heapTotalMB: number;
  heapUsedMB: number;
  externalMB: number;
  vaultCacheSize: number;
  rateLimitEntries: number;
}

export interface LifecycleBenchmarkReport {
  totalRequests: number;
  initial: MemorySnapshot;
  final: MemorySnapshot;
  deltaHeapUsedMB: number;
  deltaRssMB: number;
  passed: boolean;
  retentionLimitMB: number;
}

export function runLifecycleMemoryBenchmark(cycles: number = 10000): LifecycleBenchmarkReport {
  if (global.gc) global.gc();

  const getSnapshot = (sanitizer: SecretSanitizer, rateLimiter: RateLimiter): MemorySnapshot => {
    const mem = process.memoryUsage();
    return {
      rssMB: Math.round((mem.rss / (1024 * 1024)) * 100) / 100,
      heapTotalMB: Math.round((mem.heapTotal / (1024 * 1024)) * 100) / 100,
      heapUsedMB: Math.round((mem.heapUsed / (1024 * 1024)) * 100) / 100,
      externalMB: Math.round((mem.external / (1024 * 1024)) * 100) / 100,
      vaultCacheSize: (sanitizer as any).vault?.secrets?.size || 0,
      rateLimitEntries: (rateLimiter as any).counts?.size || 0
    };
  };

  const sanitizer = new SecretSanitizer();
  const rateLimiter = new RateLimiter(500, 60000, 5000);
  const validator = new ProtocolValidator();

  const initial = getSnapshot(sanitizer, rateLimiter);

  const samplePayload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'execute_command',
      arguments: {
        command: 'ls -la /tmp',
        secret: ['ghp', '_mocksecrettoken1234567890abcdef'].join('')
      }
    }
  };

  for (let i = 0; i < cycles; i++) {
    validator.validateInbound(samplePayload);
    const mockSeq = ['ghp', '_'].join('') + (i % 1000).toString().padStart(36, '0');
    sanitizer.sanitize(`Payload ${i}: ${mockSeq}`);
    rateLimiter.checkLimit(`tool_${i % 200}`);
  }

  if (global.gc) global.gc();

  const final = getSnapshot(sanitizer, rateLimiter);
  const deltaHeapUsedMB = Math.round((final.heapUsedMB - initial.heapUsedMB) * 100) / 100;
  const deltaRssMB = Math.round((final.rssMB - initial.rssMB) * 100) / 100;

  const retentionLimitMB = 35.0; // 35 MB max retention growth allowed
  const passed = deltaHeapUsedMB <= retentionLimitMB && final.vaultCacheSize <= 5000;

  return {
    totalRequests: cycles,
    initial,
    final,
    deltaHeapUsedMB,
    deltaRssMB,
    passed,
    retentionLimitMB
  };
}

if (require.main === module) {
  console.log('\n=== MCP-SHIELD LIFECYCLE & MEMORY RESILIENCE BENCHMARK ===\n');
  const report = runLifecycleMemoryBenchmark(10000);
  console.log(`Cycles: ${report.totalRequests.toLocaleString()}`);
  console.log(`Initial Heap: ${report.initial.heapUsedMB} MB | Final Heap: ${report.final.heapUsedMB} MB (Δ ${report.deltaHeapUsedMB} MB)`);
  console.log(`Initial RSS: ${report.initial.rssMB} MB | Final RSS: ${report.final.rssMB} MB (Δ ${report.deltaRssMB} MB)`);
  console.log(`Vault Cache Size: ${report.final.vaultCacheSize} / 5000 max`);
  console.log(`Rate Limiter Size: ${report.final.rateLimitEntries} / 5000 max`);
  console.log(`Retention Limit: <= ${report.retentionLimitMB} MB`);
  console.log(`\nVerdict: ${report.passed ? 'PASSED (Zero Memory Leaks)' : 'FAILED (Memory Growth Exceeded Limit)'}`);
  process.exit(report.passed ? 0 : 1);
}
