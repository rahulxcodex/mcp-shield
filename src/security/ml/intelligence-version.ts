/**
 * MCP Shield - Security Intelligence Version Identity
 * Step 3 Roadmap - Section 14 & Milestone E
 *
 * Implements cryptographic fingerprinting and provenance for:
 * - Model artifacts
 * - Feature schemas
 * - Training datasets
 * - Security rule definitions
 * - Attack corpus snapshots
 */

import { hashCanonicalJson } from '../canonical-json';
import { FEATURE_SCHEMA_VERSION } from './feature-extractor';
import { TabularRiskModel } from './models/tabular-risk-model';
import { TextSecurityClassifier } from './models/text-security-classifier';
import { BehaviorAnomalyDetector } from './models/behavior-anomaly-detector';

export interface SecurityIntelligenceVersion {
  buildId: string;
  combinedFingerprint: string;
  releaseDate: string;
  models: {
    modelA: { id: string; version: string; hash: string };
    modelB: { id: string; version: string; hash: string };
    modelC: { id: string; version: string; hash: string };
  };
  featureSchema: {
    version: string;
    featureCount: number;
    hash: string;
  };
  datasets: {
    trainingDatasetVersion: string;
    attackCorpusVersion: string;
  };
  securityRulesVersion: string;
}

export class SecurityIntelligenceRegistry {
  private static activeVersion: SecurityIntelligenceVersion | null = null;

  public static getActiveVersion(): SecurityIntelligenceVersion {
    if (!this.activeVersion) {
      this.activeVersion = this.computeVersion({
        trainingDatasetVersion: 'ds-2026.09-v1',
        attackCorpusVersion: 'corpus-2026.09-v1',
        securityRulesVersion: 'rules-v2.4'
      });
    }
    return this.activeVersion;
  }

  public static computeVersion(config: {
    trainingDatasetVersion: string;
    attackCorpusVersion: string;
    securityRulesVersion: string;
  }): SecurityIntelligenceVersion {
    const modelAHash = hashCanonicalJson({ id: TabularRiskModel.MODEL_ID, ver: TabularRiskModel.MODEL_VERSION });
    const modelBHash = hashCanonicalJson({ id: TextSecurityClassifier.MODEL_ID, ver: TextSecurityClassifier.MODEL_VERSION });
    const modelCHash = hashCanonicalJson({ id: BehaviorAnomalyDetector.MODEL_ID, ver: BehaviorAnomalyDetector.MODEL_VERSION });
    const featureSchemaHash = hashCanonicalJson({ ver: FEATURE_SCHEMA_VERSION });

    const combinedManifest = {
      modelA: { id: TabularRiskModel.MODEL_ID, version: TabularRiskModel.MODEL_VERSION, hash: modelAHash },
      modelB: { id: TextSecurityClassifier.MODEL_ID, version: TextSecurityClassifier.MODEL_VERSION, hash: modelBHash },
      modelC: { id: BehaviorAnomalyDetector.MODEL_ID, version: BehaviorAnomalyDetector.MODEL_VERSION, hash: modelCHash },
      featureSchema: { version: FEATURE_SCHEMA_VERSION, featureCount: 42, hash: featureSchemaHash },
      datasets: {
        trainingDatasetVersion: config.trainingDatasetVersion,
        attackCorpusVersion: config.attackCorpusVersion
      },
      securityRulesVersion: config.securityRulesVersion
    };

    const combinedFingerprint = hashCanonicalJson(combinedManifest);
    const buildId = `INTEL-${combinedFingerprint.slice(0, 12).toUpperCase()}`;

    return {
      buildId,
      combinedFingerprint,
      releaseDate: new Date().toISOString(),
      models: combinedManifest.modelA && {
        modelA: combinedManifest.modelA,
        modelB: combinedManifest.modelB,
        modelC: combinedManifest.modelC
      },
      featureSchema: combinedManifest.featureSchema,
      datasets: combinedManifest.datasets,
      securityRulesVersion: combinedManifest.securityRulesVersion
    };
  }
}
