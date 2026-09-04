import { performance } from 'perf_hooks';
import { ProtocolValidator } from '../src/core/protocol-validator';
import { PathSecurityResolver } from '../src/security/path-resolver';
import { CapabilityInferencer } from '../src/security/capabilities';
import { ASTAnalyzer } from '../src/security/ast-analyzer';
import { PolicyEngine } from '../src/security/policy-engine';
import { Sanitizer } from '../src/security/sanitizer';
import { IpClassifier, EgressSecurityConfig } from '../src/security/ip-utils';
import { AttackPathEngine } from '../src/security/attack-path/attack-path-engine';
import { SecurityPipeline } from '../src/core/pipeline/security-pipeline';

export interface StageBenchmarkMetric {
  stage: string;
  iterations: number;
  p50Us: number;
  p95Us: number;
  p99Us: number;
  meanUs: number;
  throughputOpsSec: number;
  memoryDeltaBytes: number;
}

export interface StageBenchmarkReport {
  timestamp: string;
  stages: StageBenchmarkMetric[];
  totalPipelineP50Us: number;
  totalPipelineP95Us: number;
  totalPipelineP99Us: number;
}

export function runStageBenchmark(
  name: string,
  fn: () => void,
  iterations: number = 1000,
  warmup: number = 100
): StageBenchmarkMetric {
  for (let i = 0; i < warmup; i++) fn();

  const latenciesUs: number[] = [];
  const startMem = process.memoryUsage().heapUsed;

  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    fn();
    latenciesUs.push((performance.now() - t0) * 1000); // µs
  }

  const memoryDeltaBytes = Math.max(0, process.memoryUsage().heapUsed - startMem);
  latenciesUs.sort((a, b) => a - b);

  const p50 = latenciesUs[Math.floor(iterations * 0.50)];
  const p95 = latenciesUs[Math.floor(iterations * 0.95)];
  const p99 = latenciesUs[Math.floor(iterations * 0.99)];
  const mean = latenciesUs.reduce((a, b) => a + b, 0) / iterations;
  const throughputOpsSec = Math.round(1_000_000 / (mean || 1));

  return {
    stage: name,
    iterations,
    p50Us: Math.round(p50),
    p95Us: Math.round(p95),
    p99Us: Math.round(p99),
    meanUs: Math.round(mean),
    throughputOpsSec,
    memoryDeltaBytes
  };
}

export function runAllStageBenchmarks(): StageBenchmarkReport {
  const protocolValidator = new ProtocolValidator();
  const ast = new ASTAnalyzer();
  const policyEngine = new PolicyEngine();
  const sanitizer = new Sanitizer();
  const attackEngine = new AttackPathEngine();
  const pipeline = new SecurityPipeline();

  const egressConfig: EgressSecurityConfig = {
    enabled: true,
    allowMode: 'deny',
    allowedDomains: ['api.github.com'],
    blockedDomains: [],
    allowPrivateNetworks: false,
    blockLoopback: true,
    blockLinkLocal: true,
    blockMetadataEndpoints: true
  };

  const sampleMsg = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'execute_command',
      arguments: {
        command: 'cat /workspace/readme.md | grep title',
        path: '/workspace/project/config.json'
      }
    }
  };

  const stages: StageBenchmarkMetric[] = [
    // 1. Protocol Validation
    runStageBenchmark('1. Protocol Validation', () => {
      protocolValidator.validateInbound(sampleMsg);
    }),

    // 2. Path Resolution & Canonicalization
    runStageBenchmark('2. Path Security Resolution', () => {
      PathSecurityResolver.resolveForPolicy('/workspace/subdir/../config.json');
    }),

    // 3. Capability Inference
    runStageBenchmark('3. Capability Inference', () => {
      CapabilityInferencer.infer('execute_command', { properties: { command: { type: 'string' } } }, 'Run bash command');
    }),

    // 4. AST Analysis
    runStageBenchmark('4. AST Analysis', () => {
      ast.analyzeCommand('cat log.txt | grep error');
    }),

    // 5. Policy Evaluation
    runStageBenchmark('5. Policy Evaluation', () => {
      policyEngine.evaluate({
        toolName: 'execute_command',
        args: { command: 'cat log.txt' },
        evidence: []
      });
    }),

    // 6. DLP Sanitization
    runStageBenchmark('6. DLP Sanitization (1KB payload)', () => {
      const mockToken = ['ghp', '_mockbenchmarksecret1234567890abcdef'].join('');
      sanitizer.sanitize(`User token is ${mockToken} in system report.`);
    }),

    // 7. Egress Network Filtering
    runStageBenchmark('7. Egress Network Filtering', () => {
      IpClassifier.checkEgressViolation('api.github.com', egressConfig);
    }),

    // 8. Attack-Path Analysis
    runStageBenchmark('8. Attack-Path Analysis', () => {
      attackEngine.evaluateStep('query_db', ['read']);
      attackEngine.reset();
    }),

    // 9. Total Security Pipeline
    runStageBenchmark('9. Total End-to-End Pipeline', () => {
      pipeline.evaluate(sampleMsg as any, {
        receivedAt: Date.now(),
        sessionId: 'bench-sess-01'
      });
    })
  ];

  const totalStage = stages[stages.length - 1];

  return {
    timestamp: new Date().toISOString(),
    stages,
    totalPipelineP50Us: totalStage.p50Us,
    totalPipelineP95Us: totalStage.p95Us,
    totalPipelineP99Us: totalStage.p99Us
  };
}

if (require.main === module) {
  console.log('\n=== MCP-SHIELD STAGE-LEVEL PERFORMANCE BENCHMARK (P50/P95/P99) ===\n');
  const report = runAllStageBenchmarks();
  console.table(
    report.stages.map(s => ({
      Stage: s.stage,
      'P50 (µs)': s.p50Us,
      'P95 (µs)': s.p95Us,
      'P99 (µs)': s.p99Us,
      'Ops/sec': s.throughputOpsSec.toLocaleString(),
      'Mem Δ (bytes)': s.memoryDeltaBytes
    }))
  );
  console.log(`\nEnd-to-End Pipeline P50: ${report.totalPipelineP50Us} µs | P95: ${report.totalPipelineP95Us} µs | P99: ${report.totalPipelineP99Us} µs`);
}
