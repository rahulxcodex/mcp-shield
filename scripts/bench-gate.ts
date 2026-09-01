import { performance } from 'perf_hooks';
import { ASTAnalyzer } from '../src/security/ast-analyzer';
import { SecretSanitizer } from '../src/security/sanitizer';
import { RateLimiter } from '../src/security/rate-limiter';
import { PolicyEngine } from '../src/security/policy-engine';
import { FormatPreservingEncryptor } from '../src/security/fpe';
import { CanaryManager } from '../src/security/canary';

interface GateCheck {
  component: string;
  measuredLatencyUs: number;
  maxAllowedUs: number;
  passed: boolean;
}

function measureMedianUs(fn: () => void, iterations: number = 2000, warmup: number = 200): number {
  for (let i = 0; i < warmup; i++) fn();
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    times.push((performance.now() - start) * 1000); // convert ms to microseconds (µs)
  }
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)]; // p50 median
}

export function runPerformanceGate(): boolean {
  console.log('\n================================================================================');
  console.log('⚡ MCP-SHIELD CI PERFORMANCE REGRESSION GATE (Enterprise Phase 1-3)');
  console.log('================================================================================\n');

  const ast = new ASTAnalyzer();
  const sanitizer = new SecretSanitizer();
  const rateLimiter = new RateLimiter(50000, 60000);
  const policyEngine = new PolicyEngine();
  const fpe = new FormatPreservingEncryptor();
  const canary = new CanaryManager();

  const sample1Kb = JSON.stringify({
    tool: 'execute_command',
    args: { command: 'echo "sk-proj-1234567890abcdef1234567890abcdef1234567890"' }
  });

  const checks: GateCheck[] = [];

  // 1. AST Simple Command
  const astSimpleP50 = measureMedianUs(() => {
    ast.analyzeCommand('ls -la /var/log');
  });
  checks.push({
    component: 'AST: Simple Command ("ls -la /var/log")',
    measuredLatencyUs: astSimpleP50,
    maxAllowedUs: 1000, // 1.0 ms ceiling
    passed: astSimpleP50 <= 1000
  });

  // 2. AST Wrapper & Pipeline Command
  const astPipeP50 = measureMedianUs(() => {
    ast.analyzeCommand("cat log | grep err | awk '{print $1}'");
  });
  checks.push({
    component: 'AST: Wrapper Pipeline ("cat log | grep ...")',
    measuredLatencyUs: astPipeP50,
    maxAllowedUs: 2000, // 2.0 ms ceiling
    passed: astPipeP50 <= 2000
  });

  // 3. Secret Sanitizer (1 KB payload)
  const sanitizerP50 = measureMedianUs(() => {
    sanitizer.sanitize(sample1Kb);
  });
  checks.push({
    component: 'Sanitizer: 1 KB Payload Scan & Redact',
    measuredLatencyUs: sanitizerP50,
    maxAllowedUs: 300, // 300 µs ceiling
    passed: sanitizerP50 <= 300
  });

  // 4. Format-Preserving Encryption (FPE Token Masking)
  const fpeP50 = measureMedianUs(() => {
    fpe.encryptAlphanumericToken('sk-proj-1234567890abcdef1234567890abcdef1234567890');
  });
  checks.push({
    component: 'FPE: Format-Preserving Token Masking',
    measuredLatencyUs: fpeP50,
    maxAllowedUs: 150, // 150 µs ceiling
    passed: fpeP50 <= 150
  });

  // 5. Canary Honeypot Tool Lookup & Tripwire
  const canaryP50 = measureMedianUs(() => {
    canary.isCanaryTool('shield_canary_system_vault_access');
  });
  checks.push({
    component: 'Canary: Honeypot Tool Interception',
    measuredLatencyUs: canaryP50,
    maxAllowedUs: 50, // 50 µs ceiling
    passed: canaryP50 <= 50
  });

  // 6. Rate Limiter Check
  const rateLimitP50 = measureMedianUs(() => {
    rateLimiter.checkLimit('test_tool');
  });
  checks.push({
    component: 'RateLimiter: In-Memory Sliding Window',
    measuredLatencyUs: rateLimitP50,
    maxAllowedUs: 50, // 50 µs ceiling
    passed: rateLimitP50 <= 50
  });

  // 7. Policy Engine Evaluation
  const policyP50 = measureMedianUs(() => {
    policyEngine.evaluate({
      toolName: 'read_file',
      args: { path: '/home/user/code/index.ts' },
      evidence: []
    });
  });
  checks.push({
    component: 'PolicyEngine: Rule Evaluation & Path Match',
    measuredLatencyUs: policyP50,
    maxAllowedUs: 100, // 100 µs ceiling
    passed: policyP50 <= 100
  });

  // Print results table
  console.log('| Component | Measured (p50) | Max Allowed Ceiling | Status |');
  console.log('| :--- | :--- | :--- | :--- |');

  let allPassed = true;
  for (const check of checks) {
    const measuredStr = `${check.measuredLatencyUs.toFixed(1)} µs`;
    const maxStr = `${check.maxAllowedUs.toFixed(1)} µs`;
    const statusStr = check.passed ? '✅ PASS' : '❌ REGRESSION';
    console.log(`| ${check.component} | ${measuredStr} | ${maxStr} | ${statusStr} |`);
    if (!check.passed) {
      allPassed = false;
    }
  }

  console.log('\n================================================================================');
  if (allPassed) {
    console.log('✅ ALL PERFORMANCE GATES PASSED (No Latency Regressions Detected)\n');
  } else {
    console.error('❌ PERFORMANCE REGRESSION DETECTED: Latency exceeded allowed ceiling!\n');
  }

  return allPassed;
}

if (require.main === module) {
  const passed = runPerformanceGate();
  process.exit(passed ? 0 : 1);
}
