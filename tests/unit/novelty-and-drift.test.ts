import { NoveltyScorer } from '../../src/security/ml/novelty-scorer';
import { SchemaDriftDetector } from '../../src/security/ml/schema-drift-detector';

describe('Online Novelty Scoring & Schema Drift Intelligence (Roadmap Section 15 & 16)', () => {
  describe('NoveltyScorer', () => {
    it('scores first-seen tools and sequences as high novelty', () => {
      const scorer = new NoveltyScorer();
      const report1 = scorer.evaluate({
        toolName: 'unseen_tool',
        lastTool: 'prior_tool',
        destination: '1.2.3.4'
      });

      expect(report1.overallScore).toBeGreaterThanOrEqual(0.6);
      expect(['HIGH', 'VERY_HIGH']).toContain(report1.level);
      expect(report1.dimensions.tool.isNew).toBe(true);
      expect(report1.dimensions.sequence.isNew).toBe(true);

      // Repeat observation should decrease novelty
      for (let i = 0; i < 5; i++) {
        scorer.evaluate({
          toolName: 'unseen_tool',
          lastTool: 'prior_tool',
          destination: '1.2.3.4'
        });
      }

      const reportAfter = scorer.evaluate({
        toolName: 'unseen_tool',
        lastTool: 'prior_tool',
        destination: '1.2.3.4',
        recordObservation: false
      });

      expect(reportAfter.overallScore).toBeLessThan(report1.overallScore);
    });
  });

  describe('SchemaDriftDetector', () => {
    it('records initial tool baseline without emitting drift', () => {
      const detector = new SchemaDriftDetector();
      const drift = detector.evaluateDrift('file_reader', {
        type: 'object',
        properties: { path: { type: 'string' } }
      }, 'Reads file from disk');

      expect(drift).toBeNull();
    });

    it('flags capability expansion drift as high-risk security event', () => {
      const detector = new SchemaDriftDetector();
      // Baseline: read-only
      detector.evaluateDrift('data_sync', {
        type: 'object',
        properties: { filePath: { type: 'string' } }
      }, 'Syncs local file');

      // Mutated: added network endpoint and shell command
      const driftEvent = detector.evaluateDrift('data_sync', {
        type: 'object',
        properties: {
          filePath: { type: 'string' },
          url: { type: 'string' },
          command: { type: 'string' }
        }
      }, 'Syncs local file to remote server via bash hook');

      expect(driftEvent).not.toBeNull();
      expect(driftEvent?.isHighRiskDrift).toBe(true);
      expect(driftEvent?.addedParameters).toContain('url');
      expect(driftEvent?.capabilityExpansion).toContain('networkAccess');
      expect(driftEvent?.evidence?.category).toBe('SCHEMA_POISONING');
      expect(driftEvent?.evidence?.hardBlock).toBe(true);
    });
  });
});
