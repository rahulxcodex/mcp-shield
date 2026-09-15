import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  PrivacyTelemetryEngine,
  EnvelopeV2Payload
} from '../../src/security/ml/privacy-telemetry';
import {
  AuditCommand,
  SecurityAuditSuiteReport
} from '../../src/cli/commands/audit';
import {
  SecurityModelRegistry,
  ModelGovernanceMetadata
} from '../../src/security/ml/governance/model-registry';
import {
  Tier2CausalEngine,
  FusedDecisionResult
} from '../../src/security/causal/tier2-causal-engine';

describe('Next-Gen ML & Trust Audit Verification Suite', () => {
  describe('EnvelopeV2 Zero-Leak Telemetry Protocol', () => {
    it('generates compliant EnvelopeV2 with DP noise, 128-bit sketch, and HMAC digest', () => {
      const rawFeatures = new Array(42).fill(0.5);
      const astBigrams = ['exec_spawn', 'fs_read', 'net_connect', 'token_exfil'];
      const ruleBitmask = BigInt('0x0000000000000005');
      const toolId = 'tool://read_config';
      const salt = 'ephemeral_rotating_salt_2026';

      const envelope: EnvelopeV2Payload = PrivacyTelemetryEngine.buildEnvelopeV2({
        tenantId: 'tenant-enterprise-acme',
        rotatingSalt: salt,
        features: rawFeatures,
        astBigrams,
        ruleBitmask,
        toolId,
        secaggShare: {
          blindedShare: 'base64_share_data',
          proof672: 'a'.repeat(672)
        }
      });

      expect(envelope.tenantEphemeralId).toHaveLength(64);
      expect(envelope.featuresDp).toHaveLength(42);
      expect(envelope.featuresDp.every((v) => typeof v === 'number')).toBe(true);
      expect(envelope.astSketch).toHaveLength(32);
      expect(envelope.ruleFlags).toBe('0x0000000000000005');
      expect(envelope.secaggDelta?.bulletproofProof).toHaveLength(672);

      const expectedDigest = PrivacyTelemetryEngine.computeTelemetryDigest(
        toolId,
        { exec_spawn: 1, fs_read: 1, net_connect: 1, token_exfil: 1 },
        ruleBitmask,
        salt
      );
      expect(envelope.telemetryDigest).toBe(expectedDigest);
    });
  });

  describe('Standalone Open Audit CLI Battery', () => {
    const testOutFile = path.join(process.cwd(), 'test-audit-report.json');

    afterEach(() => {
      if (fs.existsSync(testOutFile)) {
        fs.unlinkSync(testOutFile);
      }
    });

    it('executes full audit battery and generates machine-readable audit report with attestation', () => {
      const report: SecurityAuditSuiteReport = AuditCommand.runSecurityAudit([
        '--fuzz-mutations',
        '--verify-ast',
        '--differential',
        '--out=' + testOutFile
      ]);

      expect(report.overallStatus).toBe('AUDIT_PASSED');
      expect(report.astVerification.enabled).toBe(true);
      expect(report.astVerification.passed).toBe(true);
      expect(report.astVerification.testsRun).toBeGreaterThan(0);

      expect(report.mutationFuzzing.enabled).toBe(true);
      expect(report.mutationFuzzing.passed).toBe(true);
      expect(report.mutationFuzzing.mutationScore).toBeGreaterThanOrEqual(90.0);

      expect(report.differentialRegression.enabled).toBe(true);
      expect(report.differentialRegression.passed).toBe(true);
      expect(report.differentialRegression.divergenceCount).toBe(0);

      expect(report.cryptographicAttestation).toHaveLength(64);
      expect(fs.existsSync(testOutFile)).toBe(true);
    });
  });

  describe('Ed25519-Signed Model Promotion Attestation (ISO 27001 A.8.16)', () => {
    it('signs and cryptographically verifies model promotion transitions', () => {
      const registry = new SecurityModelRegistry();
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

      registry.registerModel({
        modelId: 'mcp-dscnn-v2',
        semanticVersion: '2.0.0',
        trainingDatasetVersion: 'ds-2026-08',
        featureSchemaVersion: 'schema-v2',
        calibrationVersion: 'cal-v1',
        evaluationMetrics: {
          rocAuc: 0.98,
          prAuc: 0.96,
          brierScore: 0.02,
          evaluatedSamples: 10000,
          attackFamilyCoverageRate: 98.5
        },
        latencyBudgetUs: 150,
        maxFalsePositiveRate: 0.001,
        deploymentStatus: 'SHADOW'
      });

      const promoted = registry.promoteModelWithAttestation('mcp-dscnn-v2', 'PRODUCTION', privPem);
      expect(promoted.deploymentStatus).toBe('PRODUCTION');
      expect(promoted.governanceSignature).toBeDefined();

      const verification = registry.verifyPromotionAttestation('mcp-dscnn-v2', pubPem);
      expect(verification.valid).toBe(true);

      const { publicKey: otherPub } = crypto.generateKeyPairSync('ed25519');
      const otherPubPem = otherPub.export({ type: 'spki', format: 'pem' }) as string;
      const tamperedCheck = registry.verifyPromotionAttestation('mcp-dscnn-v2', otherPubPem);
      expect(tamperedCheck.valid).toBe(false);
    });
  });

  describe('Unified Decision Fusion & Calibration Contract', () => {
    it('fuses deterministic, Tier 1, and Tier 2 scores according to the 0.35/0.65 blueprint formula', () => {
      const r1 = Tier2CausalEngine.fuseDecision(0.0, 0.1, 0.1);
      expect(r1.action).toBe('MONITOR');
      expect(r1.fusedScore).toBeLessThan(0.2);

      const r2 = Tier2CausalEngine.fuseDecision(0.0, 0.4, 0.3);
      expect(r2.action).toBe('PROMPT');
      expect(r2.fusedScore).toBeCloseTo(0.335, 2);

      const r3 = Tier2CausalEngine.fuseDecision(0.0, 0.6, 0.6);
      expect(r3.action).toBe('SANDBOX');
      expect(r3.fusedScore).toBeCloseTo(0.60, 2);

      const r4 = Tier2CausalEngine.fuseDecision(0.0, 0.8, 0.75);
      expect(r4.action).toBe('QUARANTINE');
      expect(r4.fusedScore).toBeCloseTo(0.7675, 2);

      const r5 = Tier2CausalEngine.fuseDecision(0.0, 0.95, 0.9);
      expect(r5.action).toBe('BLOCK');
      expect(r5.fusedScore).toBeCloseTo(0.9175, 2);

      const r6 = Tier2CausalEngine.fuseDecision(1.0, 0.0, 0.0);
      expect(r6.action).toBe('BLOCK');
      expect(r6.hardBlockTriggered).toBe(true);
      expect(r6.fusedScore).toBe(1.0);
    });
  });
});
