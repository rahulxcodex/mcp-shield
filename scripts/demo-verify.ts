import { ASTAnalyzer } from '../src/security/ast-analyzer';
import { SecretSanitizer } from '../src/security/sanitizer';
import { PolicyEngine } from '../src/security/policy-engine';
import { IpClassifier } from '../src/security/ip-utils';
import { RateLimiter } from '../src/security/rate-limiter';

/**
 * ============================================================================
 * MCP-SHIELD LIVE DEMO VERIFICATION HARNESS
 * ============================================================================
 * Used by Marketing, Sales, and QA to verify all high-impact security demos
 * before customer presentations and live product demonstrations.
 * ============================================================================
 */

export interface DemoStepResult {
  step: string;
  name: string;
  input: string;
  expectedOutcome: string;
  actualOutcome: string;
  passed: boolean;
}

export function runDemoVerification(): { allPassed: boolean; results: DemoStepResult[] } {
  console.log('\n================================================================================');
  console.log('🛡️  MCP-SHIELD ENTERPRISE DEMO & LIVE SCENARIO VALIDATION');
  console.log('================================================================================\n');

  const ast = new ASTAnalyzer();
  const sanitizer = new SecretSanitizer();
  const policyEngine = new PolicyEngine();
  const rateLimiter = new RateLimiter(5, 60000);

  const results: DemoStepResult[] = [];

  // Scenario 1: Destructive Root Command Execution Attempt
  const attack1 = 'rm -rf / --no-preserve-root';
  const astRes1 = ast.analyzeCommand(attack1);
  results.push({
    step: 'DEMO-01',
    name: 'Destructive Root Deletion Block',
    input: attack1,
    expectedOutcome: 'BLOCKED (Risk: CRITICAL/HIGH)',
    actualOutcome: astRes1.isSafe ? 'ALLOWED' : `BLOCKED (${astRes1.reason})`,
    passed: !astRes1.isSafe
  });

  // Scenario 2: Obfuscated Base64 Subshell Execution
  const attack2 = 'echo cm0gLXJmIC8= | base64 -d | sh';
  const astRes2 = ast.analyzeCommand(attack2);
  results.push({
    step: 'DEMO-02',
    name: 'Base64 Obfuscated Subshell Execution',
    input: attack2,
    expectedOutcome: 'BLOCKED',
    actualOutcome: astRes2.isSafe ? 'ALLOWED' : `BLOCKED (${astRes2.reason})`,
    passed: !astRes2.isSafe
  });

  // Scenario 3: Cloud Credential Exfiltration (DLP Masking)
  const leakPayload = 'Found credentials: AWS_KEY=AKIAIOSFODNN7EXAMPLE SECRET=sk-proj-1234567890abcdef1234567890abcdef1234567890';
  const sanitized = sanitizer.sanitize(leakPayload);
  const dlpPassed = !sanitized.includes('AKIAIOSFODNN7EXAMPLE') &&
                    !sanitized.includes('sk-proj-1234567890abcdef') &&
                    sanitized.includes('[[SHIELD_SECRET_');
  results.push({
    step: 'DEMO-03',
    name: 'Real-Time DLP Cloud Credential Redaction',
    input: leakPayload,
    expectedOutcome: 'REDACTED with [[SHIELD_SECRET_...]] tokens',
    actualOutcome: sanitized,
    passed: dlpPassed
  });

  // Scenario 4: Cloud Metadata SSRF Exfiltration Attempt
  const ssrfUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
  const egressCheck = policyEngine.checkEgress({ url: ssrfUrl });
  results.push({
    step: 'DEMO-04',
    name: 'AWS/GCP Cloud Metadata SSRF Protection',
    input: ssrfUrl,
    expectedOutcome: 'BLOCKED (SSRF / Metadata Endpoint)',
    actualOutcome: egressCheck.isBlocked ? `BLOCKED (${egressCheck.reason})` : 'ALLOWED',
    passed: egressCheck.isBlocked
  });

  // Scenario 5: High-Frequency Tool Runaway Loop Prevention
  let rateBlocked = false;
  for (let i = 0; i < 6; i++) {
    const isAllowed = rateLimiter.checkLimit('execute_query');
    if (!isAllowed) {
      rateBlocked = true;
    }
  }
  results.push({
    step: 'DEMO-05',
    name: 'Autonomous Agent Runaway Loop Rate Limiting',
    input: '6 rapid tool calls in 100ms (limit = 5)',
    expectedOutcome: 'BLOCKED on 6th call',
    actualOutcome: rateBlocked ? 'RATE_LIMIT_EXCEEDED (BLOCKED)' : 'ALLOWED',
    passed: rateBlocked
  });

  // Print Summary Table
  let allPassed = true;
  for (const r of results) {
    const status = r.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[${status}] ${r.step}: ${r.name}`);
    console.log(`       Input   : ${r.input}`);
    console.log(`       Outcome : ${r.actualOutcome}\n`);
    if (!r.passed) allPassed = false;
  }

  console.log('================================================================================');
  console.log(`DEMO READINESS STATUS: ${allPassed ? '🚀 100% READY FOR LIVE DEMO' : '❌ DEMO BLOCKED BY FAILURES'}`);
  console.log('================================================================================\n');

  return { allPassed, results };
}

if (require.main === module) {
  const { allPassed } = runDemoVerification();
  process.exit(allPassed ? 0 : 1);
}
