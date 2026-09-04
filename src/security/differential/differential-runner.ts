import { performance } from 'perf_hooks';

export interface DifferentialAnalyzerResult {
  decision: 'ALLOW' | 'BLOCK' | 'QUARANTINE' | 'PROMPT';
  severity: number;
  evidenceCategories: string[];
  normalizedRepresentation: string;
  latencyMs: number;
}

export interface DifferentialComparisonReport {
  input: string;
  diverged: boolean;
  divergenceDetails?: string;
  candidateResult: DifferentialAnalyzerResult;
  referenceResult: DifferentialAnalyzerResult;
}

export class DifferentialRegressionRunner {
  /**
   * Compares a candidate analyzer against a reference analyzer on a payload
   */
  public static compare(
    input: string,
    candidateFn: (cmd: string) => { isSafe: boolean; reason?: string; normalized?: string },
    referenceFn: (cmd: string) => { isSafe: boolean; reason?: string; normalized?: string }
  ): DifferentialComparisonReport {
    // Run candidate
    const t0 = performance.now();
    const cand = candidateFn(input);
    const candLatency = performance.now() - t0;

    // Run reference
    const t1 = performance.now();
    const ref = referenceFn(input);
    const refLatency = performance.now() - t1;

    const candidateResult: DifferentialAnalyzerResult = {
      decision: cand.isSafe ? 'ALLOW' : 'BLOCK',
      severity: cand.isSafe ? 0.0 : 0.9,
      evidenceCategories: cand.isSafe ? [] : ['COMMAND_INJECTION'],
      normalizedRepresentation: cand.normalized || input.trim(),
      latencyMs: candLatency
    };

    const referenceResult: DifferentialAnalyzerResult = {
      decision: ref.isSafe ? 'ALLOW' : 'BLOCK',
      severity: ref.isSafe ? 0.0 : 0.9,
      evidenceCategories: ref.isSafe ? [] : ['COMMAND_INJECTION'],
      normalizedRepresentation: ref.normalized || input.trim(),
      latencyMs: refLatency
    };

    const decisionDiverged = candidateResult.decision !== referenceResult.decision;
    const details = decisionDiverged
      ? `Decision divergence: Candidate decided ${candidateResult.decision}, but Reference decided ${referenceResult.decision}`
      : undefined;

    return {
      input,
      diverged: decisionDiverged,
      divergenceDetails: details,
      candidateResult,
      referenceResult
    };
  }

  /**
   * Evaluates an entire suite of inputs, returning only diverged entries
   */
  public static evaluateCorpus(
    inputs: string[],
    candidateFn: (cmd: string) => { isSafe: boolean; reason?: string; normalized?: string },
    referenceFn: (cmd: string) => { isSafe: boolean; reason?: string; normalized?: string }
  ): DifferentialComparisonReport[] {
    return inputs.map(input => this.compare(input, candidateFn, referenceFn));
  }
}
