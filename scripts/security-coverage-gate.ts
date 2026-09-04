import * as fs from 'fs';
import * as path from 'path';

export interface CoverageMetric {
  total: number;
  covered: number;
  skipped: number;
  pct: number;
}

export interface FileCoverage {
  lines: CoverageMetric;
  functions: CoverageMetric;
  statements: CoverageMetric;
  branches: CoverageMetric;
}

export interface SecurityCoverageGateResult {
  passed: boolean;
  globalCoverage: {
    linesPct: number;
    statementsPct: number;
    functionsPct: number;
    branchesPct: number;
  };
  criticalModules: Array<{
    category: string;
    path: string;
    targetPct: number;
    actualPct: number;
    passed: boolean;
  }>;
  summary: string;
}

export class SecurityCoverageEvaluator {
  private static readonly CRITICAL_SECURITY_TARGETS: Array<{
    category: string;
    globOrFile: string;
    targetPct: number;
  }> = [
    { category: 'Path Resolver', globOrFile: 'src/security/path-resolver.ts', targetPct: 95 },
    { category: 'Egress Controls', globOrFile: 'src/security/ip-utils.ts', targetPct: 95 },
    { category: 'Network Proxy', globOrFile: 'src/security/network-proxy.ts', targetPct: 80 },
    { category: 'Protocol Validator', globOrFile: 'src/core/protocol-validator.ts', targetPct: 90 },
    { category: 'Policy Engine', globOrFile: 'src/security/policy-engine.ts', targetPct: 90 },
    { category: 'AST Security Parser', globOrFile: 'src/security/ast-analyzer.ts', targetPct: 90 },
    { category: 'Capabilities Logic', globOrFile: 'src/security/capabilities.ts', targetPct: 90 },
    { category: 'Unicode Normalizer', globOrFile: 'src/security/unicode-normalizer.ts', targetPct: 95 }
  ];

  public static evaluate(summaryPath: string): SecurityCoverageGateResult {
    if (!fs.existsSync(summaryPath)) {
      throw new Error(`Coverage summary not found at: ${summaryPath}. Run test:coverage first.`);
    }

    const raw = fs.readFileSync(summaryPath, 'utf8');
    const summary = JSON.parse(raw);

    const total = summary.total as FileCoverage;
    const globalCoverage = {
      linesPct: total.lines.pct,
      statementsPct: total.statements.pct,
      functionsPct: total.functions.pct,
      branchesPct: total.branches.pct
    };

    const criticalResults = this.CRITICAL_SECURITY_TARGETS.map(item => {
      // Find matching file in summary keys
      const matchingKey = Object.keys(summary).find(k => k.replace(/\\/g, '/').includes(item.globOrFile));
      if (!matchingKey) {
        return {
          category: item.category,
          path: item.globOrFile,
          targetPct: item.targetPct,
          actualPct: 0,
          passed: false
        };
      }

      const fileCov = summary[matchingKey] as FileCoverage;
      const actualPct = fileCov.lines.pct;
      return {
        category: item.category,
        path: item.globOrFile,
        targetPct: item.targetPct,
        actualPct,
        passed: actualPct >= item.targetPct
      };
    });

    const failedCritical = criticalResults.filter(r => !r.passed);
    const passed = failedCritical.length === 0;

    return {
      passed,
      globalCoverage,
      criticalModules: criticalResults,
      summary: passed
        ? `Security Coverage Gate Passed: Global ${globalCoverage.linesPct}%, Critical Modules: All passed.`
        : `Security Coverage Gate Failed: Regressions in: ${failedCritical.map(f => `${f.category} (${f.actualPct}% < ${f.targetPct}%)`).join(', ')}`
    };
  }
}

// CLI Execution
if (require.main === module) {
  const coverageSummaryFile = path.resolve(__dirname, '../coverage/coverage-summary.json');
  try {
    const result = SecurityCoverageEvaluator.evaluate(coverageSummaryFile);
    console.log('\n=== MCP-SHIELD SECURITY-WEIGHTED COVERAGE GATE ===');
    console.log(`Global Lines: ${result.globalCoverage.linesPct}% | Statements: ${result.globalCoverage.statementsPct}%`);
    console.log('--- Critical Security Modules ---');
    for (const m of result.criticalModules) {
      const status = m.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`[${status}] ${m.category} (${m.path}): ${m.actualPct}% / target: ${m.targetPct}%`);
    }
    console.log(`\nVerdict: ${result.passed ? 'PASSED' : 'FAILED'}`);
    process.exit(result.passed ? 0 : 1);
  } catch (err: any) {
    console.error('Error evaluating coverage:', err.message);
    process.exit(1);
  }
}
