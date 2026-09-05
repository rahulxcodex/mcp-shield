import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { verifyIpBoundary } from './verify-ip-boundary';
import { AttackFamilyCoverageGate } from './attack-family-coverage-gate';
import { runAllStageBenchmarks } from '../benchmarks/stage-level-pipeline.bench';

interface ChecklistItem {
  id: string;
  phase: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  verificationMethod: string;
  target: string;
  status: 'PASS' | 'FAIL' | 'NOT_APPLICABLE';
}

interface Checklist {
  name: string;
  version: string;
  evaluatedAt: string;
  summary: {
    totalControls: number;
    criticalControls: number;
    highControls: number;
    mediumControls: number;
    status: string;
  };
  controls: ChecklistItem[];
}

export async function runChecklistVerification(): Promise<{ passed: boolean; failures: number; total: number }> {
  const checklistPath = path.resolve(__dirname, '../docs/production-checklist.json');
  if (!fs.existsSync(checklistPath)) {
    console.error('ERROR: docs/production-checklist.json not found!');
    process.exit(1);
  }

  const checklist: Checklist = JSON.parse(fs.readFileSync(checklistPath, 'utf8'));
  console.log('\n============================================================');
  console.log(' EVALUATING MCP SHIELD PRODUCTION READINESS GATES');
  console.log(` Specification: ${checklist.name} (v${checklist.version})`);
  console.log(` Controls to evaluate: ${checklist.controls.length}`);
  console.log('============================================================\n');

  let failures = 0;
  let passed = 0;

  // Cached test suite results to avoid redundant test executions
  const suiteCache = new Map<string, { success: boolean; output: string }>();

  function runSubprocessTest(cwd: string, cmd: string, args: string[]): { success: boolean; output: string } {
    const key = `${cwd}:${cmd}:${args.join(' ')}`;
    if (suiteCache.has(key)) {
      return suiteCache.get(key)!;
    }
    const result = spawnSync(cmd, args, {
      cwd,
      env: { ...process.env, NODE_ENV: 'test' },
      encoding: 'utf8',
      shell: process.platform === 'win32'
    });
    const success = result.status === 0;
    const output = (result.stdout || '') + (result.stderr || '');
    const entry = { success, output };
    suiteCache.set(key, entry);
    return entry;
  }

  // Pre-run Jest suite for mcp-shield unit/integration test controls
  console.log('[PRE-FLIGHT] Running core Jest test suites in mcp-shield...');
  const jestSuites = [
    'tests/security-corpus/protocol-property-based.test.ts',
    'tests/redteam/ast-evasion-redteam.test.ts',
    'tests/unit/container-sandbox.test.ts',
    'tests/unit/config-safety.test.ts',
    'tests/security/race-concurrency.test.ts',
    'tests/unit/cache-integrity.test.ts',
    'tests/unit/audit-ledger-tamper.test.ts',
    'tests/integration/full-e2e-journey.test.ts'
  ];
  const jestResult = runSubprocessTest(
    path.resolve(__dirname, '..'),
    'node',
    ['scripts/run-tests.js', ...jestSuites]
  );
  if (!jestResult.success) {
    console.error('[PRE-FLIGHT ERROR] Core Jest test suites failed:\n' + jestResult.output.slice(-500));
  } else {
    console.log('      ✓ Core Jest test suites passed (8 suites verified)\n');
  }

  for (const control of checklist.controls) {
    let checkPassed = true;
    let detail = '';

    const targetPath = path.resolve(__dirname, '..', control.target);
    if (!fs.existsSync(targetPath)) {
      checkPassed = false;
      detail = `Target missing: ${control.target}`;
      failures++;
      console.error(` [FAIL] [${control.severity.padEnd(8)}] ${control.id}: ${control.title} - ${detail}`);
      continue;
    }

    try {
      switch (control.id) {
        case 'SEC-GATE-001': {
          // Verify contract definitions and non-negotiables in PRODUCTION_READINESS.md
          const content = fs.readFileSync(targetPath, 'utf8');
          const hasSLO = content.includes('SLO') && (content.includes('P95') || content.includes('P99'));
          const hasModes = content.includes('Embedded Library') || content.includes('Deployment Mode');
          if (!hasSLO || !hasModes || content.length < 1000) {
            checkPassed = false;
            detail = 'PRODUCTION_READINESS.md lacks required SLO or deployment specifications';
          }
          break;
        }

        case 'SEC-GATE-002': {
          // Verify zero fallback credentials in environment configs
          const mcpEnv = fs.readFileSync(targetPath, 'utf8');
          const licensingEnvPath = path.resolve(__dirname, '../../mcp-shield-licensing/src/lib/config.ts');
          const licensingEnv = fs.existsSync(licensingEnvPath) ? fs.readFileSync(licensingEnvPath, 'utf8') : '';
          if (
            mcpEnv.includes('test-service-key-for-local-mock-only') ||
            licensingEnv.includes('test-service-key-for-local-mock-only') ||
            licensingEnv.includes('placeholder.supabase.co')
          ) {
            checkPassed = false;
            detail = 'Forbidden hardcoded mock secret detected in environment configuration';
          }
          break;
        }

        case 'SEC-GATE-003':
        case 'SEC-GATE-004':
        case 'SEC-GATE-005':
        case 'SEC-GATE-015':
        case 'SEC-GATE-016':
        case 'SEC-GATE-019':
        case 'SEC-GATE-020':
        case 'SEC-GATE-021': {
          // Verified via pre-flight Jest execution
          if (!jestResult.success) {
            checkPassed = false;
            detail = `Jest test suite execution failed for ${control.target}`;
          }
          break;
        }

        case 'SEC-GATE-006': {
          // Streaming Bijective DLP benchmark
          const dlpResult = runSubprocessTest(
            path.resolve(__dirname, '..'),
            'npx',
            ['tsx', 'benchmarks/secret-detection.bench.ts']
          );
          if (!dlpResult.success || !dlpResult.output.includes('100.00%')) {
            checkPassed = false;
            detail = 'DLP baseline benchmark precision/recall fell below 100%';
          }
          break;
        }

        case 'SEC-GATE-007':
        case 'SEC-GATE-008': {
          // Enterprise Intel test suite
          const intelDir = path.resolve(__dirname, '../../mcp-shield-enterprise-intel');
          const intelResult = runSubprocessTest(intelDir, 'node', ['tests/verify-intel.js']);
          if (!intelResult.success || !intelResult.output.includes('ENTERPRISE INTEL PRODUCTION READINESS TESTS PASSED')) {
            checkPassed = false;
            detail = 'Enterprise intel production test suite failed';
          }
          break;
        }

        case 'SEC-GATE-009':
        case 'SEC-GATE-011':
        case 'SEC-GATE-012':
        case 'SEC-GATE-013':
        case 'SEC-GATE-014': {
          // Licensing production gates
          const licDir = path.resolve(__dirname, '../../mcp-shield-licensing');
          const licResult = runSubprocessTest(licDir, 'npx', ['tsx', 'tests/licensing-production-gates.test.ts']);
          if (!licResult.success || !licResult.output.includes('ALL 7 LICENSING CONTROL PLANE PRODUCTION TESTS PASSED')) {
            checkPassed = false;
            detail = 'Licensing production gates test suite failed';
          }
          break;
        }

        case 'SEC-GATE-010': {
          // Multi-tenant IDOR & RBAC relational tests
          const licDir = path.resolve(__dirname, '../../mcp-shield-licensing');
          const idorResult = runSubprocessTest(licDir, 'npx', ['tsx', 'tests/tenant-idor-authorization.test.ts']);
          if (!idorResult.success || !idorResult.output.includes('IDOR & RBAC CHECKS PASSED')) {
            checkPassed = false;
            detail = 'Multi-tenant IDOR authorization test suite failed';
          }
          break;
        }

        case 'SEC-GATE-017': {
          // Database schema integrity & constraints
          const licDir = path.resolve(__dirname, '../../mcp-shield-licensing');
          const schemaResult = runSubprocessTest(licDir, 'npx', ['tsx', 'tests/schema-integrity.test.ts']);
          if (!schemaResult.success || !schemaResult.output.includes('ALL DATABASE SCHEMA & RLS INTEGRITY CHECKS PASSED')) {
            checkPassed = false;
            detail = 'Database schema integrity verification failed';
          }
          break;
        }

        case 'SEC-GATE-018': {
          // Stage-level latency benchmark P99 check
          const benchReport = runAllStageBenchmarks();
          if (benchReport.totalPipelineP99Us > 15000) {
            checkPassed = false;
            detail = `Pipeline P99 exceeded 15,000 µs limit (${benchReport.totalPipelineP99Us} µs)`;
          }
          break;
        }

        case 'SEC-GATE-022': {
          // Attack family coverage gate (all 8 families, 6 dimensions)
          const attackCoverage = await AttackFamilyCoverageGate.evaluateAll();
          if (!attackCoverage.passed || attackCoverage.coverageRate < 100) {
            checkPassed = false;
            detail = `Attack family coverage fell below 100% (${attackCoverage.coverageRate}%)`;
          }
          break;
        }

        case 'SEC-GATE-023': {
          // Supply chain CycloneDX SBOM generation
          const sbomResult = runSubprocessTest(
            path.resolve(__dirname, '..'),
            'node',
            ['scripts/generate-sbom.js']
          );
          if (!sbomResult.success || !sbomResult.output.includes('Compliance Audit Completed Successfully')) {
            checkPassed = false;
            detail = 'CycloneDX SBOM generation failed';
          }
          break;
        }

        case 'SEC-GATE-024': {
          // Security regression gate report
          const regReportPath = path.resolve(__dirname, '../security-report.json');
          if (!fs.existsSync(regReportPath)) {
            checkPassed = false;
            detail = 'security-report.json missing; run security-regression-gate first';
          } else {
            const regData = JSON.parse(fs.readFileSync(regReportPath, 'utf8'));
            if (regData.verdict !== 'PASSED' || !regData.summary?.allPassed) {
              checkPassed = false;
              detail = 'Security regression gate report indicates failure';
            }
          }
          break;
        }

        case 'SEC-GATE-025': {
          // Deployment hardening (render.yaml, Dockerfile)
          const renderYaml = fs.readFileSync(targetPath, 'utf8');
          const dockerfilePath = path.resolve(__dirname, '../Dockerfile');
          const dockerfile = fs.existsSync(dockerfilePath) ? fs.readFileSync(dockerfilePath, 'utf8') : '';
          const hasNonRoot = dockerfile.includes('USER node');
          const hasHealthProbe = renderYaml.includes('healthCheckPath') || renderYaml.includes('/health');
          if (!hasNonRoot || !hasHealthProbe) {
            checkPassed = false;
            detail = 'Deployment configs lack non-root user or health probes';
          }
          break;
        }

        case 'SEC-GATE-026': {
          // Disaster recovery drill
          const drResult = runSubprocessTest(
            path.resolve(__dirname, '..'),
            'npx',
            ['tsx', 'scripts/disaster-recovery-drill.ts']
          );
          if (!drResult.success || !drResult.output.includes('DRILL COMPLETE: PASS')) {
            checkPassed = false;
            detail = 'Disaster recovery restoration drill failed';
          }
          break;
        }

        case 'SEC-GATE-027': {
          // IP boundary check
          const boundaryResult = verifyIpBoundary();
          if (!boundaryResult.passed) {
            checkPassed = false;
            detail = `IP boundary violations: ${boundaryResult.violations.join(', ')}`;
          }
          break;
        }

        case 'SEC-GATE-028': {
          // Concrete production blockers resolution
          const certPath = path.resolve(__dirname, '../reports/production-certification.json');
          if (!fs.existsSync(certPath)) {
            checkPassed = false;
            detail = 'reports/production-certification.json missing';
          }
          break;
        }

        default: {
          // Generic boundary_check fallback
          if (control.verificationMethod === 'boundary_check') {
            const boundaryResult = verifyIpBoundary();
            if (!boundaryResult.passed) {
              checkPassed = false;
              detail = `IP boundary check failed: ${boundaryResult.violations.join(', ')}`;
            }
          }
        }
      }
    } catch (err: any) {
      checkPassed = false;
      detail = `Exception during evaluation: ${err.message}`;
    }

    if (checkPassed) {
      passed++;
      console.log(` [PASS] [${control.severity.padEnd(8)}] ${control.id}: ${control.title}`);
    } else {
      failures++;
      console.error(` [FAIL] [${control.severity.padEnd(8)}] ${control.id}: ${control.title} - ${detail}`);
    }
  }

  console.log('\n------------------------------------------------------------');
  console.log(` Summary: ${passed} Passed, ${failures} Failed out of ${checklist.controls.length} controls.`);
  console.log(` Status: ${failures === 0 ? 'PRODUCTION READY' : 'GATES FAILED'}`);
  console.log('------------------------------------------------------------\n');

  return { passed: failures === 0, failures, total: checklist.controls.length };
}

if (require.main === module) {
  runChecklistVerification().then(({ passed }) => {
    process.exit(passed ? 0 : 1);
  }).catch((err) => {
    console.error('Fatal checklist verification error:', err);
    process.exit(1);
  });
}

