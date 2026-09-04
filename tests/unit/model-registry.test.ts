import { SecurityModelRegistry } from '../../src/security/ml/governance/model-registry';

describe('SecurityModelRegistry (Roadmap Section 7.3 & 7.5)', () => {
  it('registers models with deterministic cryptographic digests', () => {
    const registry = new SecurityModelRegistry();
    const model = registry.registerModel({
      modelId: 'tabular-risk-v1',
      semanticVersion: '1.0.0',
      trainingDatasetVersion: 'ds-2026-08',
      featureSchemaVersion: 'fs-v2.1',
      calibrationVersion: 'cal-v1',
      evaluationMetrics: {
        rocAuc: 0.94,
        prAuc: 0.91,
        brierScore: 0.05,
        evaluatedSamples: 10000,
        attackFamilyCoverageRate: 98.5
      },
      latencyBudgetUs: 250,
      maxFalsePositiveRate: 0.02,
      deploymentStatus: 'PRODUCTION'
    });

    expect(model.cryptographicDigest).toBeDefined();
    expect(registry.getActiveProductionModel()?.modelId).toBe('tabular-risk-v1');
  });

  it('blocks promotion to PRODUCTION if model metrics do not meet gates', () => {
    const registry = new SecurityModelRegistry();
    registry.registerModel({
      modelId: 'underperforming-model',
      semanticVersion: '0.9.0',
      trainingDatasetVersion: 'ds-raw',
      featureSchemaVersion: 'fs-v1',
      calibrationVersion: 'cal-v0',
      evaluationMetrics: {
        rocAuc: 0.82, // Below 0.90 gate
        prAuc: 0.75,
        brierScore: 0.15,
        evaluatedSamples: 500,
        attackFamilyCoverageRate: 85.0 // Below 95% gate
      },
      latencyBudgetUs: 500,
      maxFalsePositiveRate: 0.05,
      deploymentStatus: 'SHADOW'
    });

    expect(() => {
      registry.promoteModel('underperforming-model', 'PRODUCTION');
    }).toThrow(/Promotion blocked: Model ROC-AUC/);
  });

  it('supports safe promotion and seamless rollback to previous stable model', () => {
    const registry = new SecurityModelRegistry();

    // Register v1 (Production)
    registry.registerModel({
      modelId: 'model-v1',
      semanticVersion: '1.0.0',
      trainingDatasetVersion: 'ds-v1',
      featureSchemaVersion: 'fs-v1',
      calibrationVersion: 'cal-v1',
      evaluationMetrics: {
        rocAuc: 0.93,
        prAuc: 0.89,
        brierScore: 0.06,
        evaluatedSamples: 5000,
        attackFamilyCoverageRate: 96.0
      },
      latencyBudgetUs: 200,
      maxFalsePositiveRate: 0.02,
      deploymentStatus: 'PRODUCTION'
    });

    // Register v2 (Shadow)
    registry.registerModel({
      modelId: 'model-v2',
      semanticVersion: '2.0.0',
      trainingDatasetVersion: 'ds-v2',
      featureSchemaVersion: 'fs-v2',
      calibrationVersion: 'cal-v2',
      evaluationMetrics: {
        rocAuc: 0.97,
        prAuc: 0.94,
        brierScore: 0.03,
        evaluatedSamples: 8000,
        attackFamilyCoverageRate: 99.0
      },
      latencyBudgetUs: 180,
      maxFalsePositiveRate: 0.01,
      deploymentStatus: 'SHADOW'
    });

    // Promote v2
    registry.promoteModel('model-v2', 'PRODUCTION');
    expect(registry.getActiveProductionModel()?.modelId).toBe('model-v2');

    // Rollback to v1
    const rolledBack = registry.rollback('model-v2');
    expect(rolledBack.modelId).toBe('model-v1');
    expect(registry.getActiveProductionModel()?.modelId).toBe('model-v1');
  });
});
