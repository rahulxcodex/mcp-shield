/**
 * MCP-Shield — CLI Benchmark Command
 * Compliant with Step 4 of the IP Value & VRIO Moat Roadmap
 */

import { MCPSecurityBenchmarkRunner } from '../../benchmarks/mcp-security-benchmark';

export class BenchmarkCommand {
  public static async run(args: string[] = []): Promise<void> {
    console.log('⚡ Initializing MCP-Shield Comprehensive Security Benchmark Suite...');
    console.log('   Evaluating 6 Core Dimensions across protocol, shell, filesystem, network, DLP & loops...\n');

    const report = await MCPSecurityBenchmarkRunner.runBenchmark();
    const formatted = MCPSecurityBenchmarkRunner.formatReportCard(report);
    console.log(formatted);

    if (args.includes('--json')) {
      console.log('\n--- JSON Benchmark Export ---');
      console.log(JSON.stringify(report, null, 2));
    }

    if (report.overallScore >= 80) {
      console.log('\n✅ MCP Security Benchmark PASSED with Enterprise Grade Rating.');
      process.exit(0);
    } else {
      console.warn('\n⚠️ MCP Security Benchmark scored below enterprise threshold (80).');
      process.exit(1);
    }
  }
}
