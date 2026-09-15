import * as crypto from 'crypto';
import { hashCanonicalJson } from '../../canonical-json';

export type ModelDeploymentStatus = 'OFFLINE' | 'SHADOW' | 'CANARY' | 'PRODUCTION' | 'ROLLED_BACK';

export interface ModelEvaluationMetrics {
  rocAuc: number;
  prAuc: number;
  brierScore: number;
  evaluatedSamples: number;
  attackFamilyCoverageRate: number;
}

export interface ModelGovernanceMetadata {
  modelId: string;
  semanticVersion: string;
  trainingDatasetVersion: string;
  featureSchemaVersion: string;
  calibrationVersion: string;
  evaluationMetrics: ModelEvaluationMetrics;
  latencyBudgetUs: number;
  maxFalsePositiveRate: number;
  deploymentStatus: ModelDeploymentStatus;
  rollbackPointer?: string;
  registeredAt: number;
  cryptographicDigest: string;
  governanceSignature?: string;
  attestationTimestamp?: number;
}

export interface PromotionGateRequirements {
  minRocAuc: number;
  minAttackFamilyCoverageRate: number;
}

/**
 * Enterprise Model Governance & Lifecycle Registry (Roadmap Section 7.3 & 7.5)
 * Enforces cryptographic provenance, performance budgets, shadow/canary promotion,
 * and deterministic rollback for machine-learned security models.
 */
export class SecurityModelRegistry {
  public static PROMOTION_GATES: PromotionGateRequirements = {
    minRocAuc: 0.90,
    minAttackFamilyCoverageRate: 95.0,
  };

  private models: Map<string, ModelGovernanceMetadata> = new Map();
  private activeProductionModelId?: string;

  /**
   * Registers a validated model into the governance registry with cryptographic fingerprint
   */
  public registerModel(
    params: Omit<ModelGovernanceMetadata, 'registeredAt' | 'cryptographicDigest'>
  ): ModelGovernanceMetadata {
    const registeredAt = Date.now();
    const digestPayload = {
      modelId: params.modelId,
      semanticVersion: params.semanticVersion,
      trainingDatasetVersion: params.trainingDatasetVersion,
      featureSchemaVersion: params.featureSchemaVersion,
      calibrationVersion: params.calibrationVersion,
      evaluationMetrics: params.evaluationMetrics,
      latencyBudgetUs: params.latencyBudgetUs,
      maxFalsePositiveRate: params.maxFalsePositiveRate,
      registeredAt
    };

    const cryptographicDigest = hashCanonicalJson(digestPayload);

    const record: ModelGovernanceMetadata = {
      ...params,
      registeredAt,
      cryptographicDigest
    };

    this.models.set(params.modelId, record);

    if (record.deploymentStatus === 'PRODUCTION') {
      this.activeProductionModelId = record.modelId;
    }

    return record;
  }

  /**
   * Promotes model through governance lifecycle (SHADOW -> CANARY -> PRODUCTION)
   */
  public promoteModel(modelId: string, targetStatus: ModelDeploymentStatus): ModelGovernanceMetadata {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model '${modelId}' not found in registry`);
    }

    // Enforce governance gating before production promotion
    if (targetStatus === 'PRODUCTION') {
      const gates = SecurityModelRegistry.PROMOTION_GATES;
      if (model.evaluationMetrics.rocAuc < gates.minRocAuc) {
        throw new Error(
          `Promotion blocked: Model ROC-AUC (${model.evaluationMetrics.rocAuc}) below minimum production gate (${gates.minRocAuc})`
        );
      }
      if (model.evaluationMetrics.attackFamilyCoverageRate < gates.minAttackFamilyCoverageRate) {
        throw new Error(
          `Promotion blocked: Attack family coverage (${model.evaluationMetrics.attackFamilyCoverageRate}%) below ${gates.minAttackFamilyCoverageRate}%`
        );
      }

      // If existing production model exists, set rollback pointer
      if (this.activeProductionModelId && this.activeProductionModelId !== modelId) {
        model.rollbackPointer = this.activeProductionModelId;
        const oldProd = this.models.get(this.activeProductionModelId);
        if (oldProd) oldProd.deploymentStatus = 'OFFLINE';
      }

      this.activeProductionModelId = modelId;
    }

    model.deploymentStatus = targetStatus;
    return model;
  }

  /**
   * Promotes model with ISO 27001 A.8.16 Ed25519-signed cryptographic attestation
   */
  public promoteModelWithAttestation(
    modelId: string,
    targetStatus: ModelDeploymentStatus,
    privateKeyPem: string
  ): ModelGovernanceMetadata {
    const model = this.promoteModel(modelId, targetStatus);
    const attestationTimestamp = Date.now();
    const canonicalPayload = hashCanonicalJson({
      modelId: model.modelId,
      semanticVersion: model.semanticVersion,
      targetStatus,
      cryptographicDigest: model.cryptographicDigest,
      rocAuc: model.evaluationMetrics.rocAuc,
      timestamp: attestationTimestamp
    });

    const signature = crypto
      .sign(null, Buffer.from(canonicalPayload, 'utf8'), privateKeyPem)
      .toString('hex');

    model.governanceSignature = signature;
    model.attestationTimestamp = attestationTimestamp;
    return model;
  }

  /**
   * Verifies ISO 27001 A.8.16 cryptographic promotion attestation against model metadata
   */
  public verifyPromotionAttestation(
    modelId: string,
    publicKeyPem: string
  ): { valid: boolean; reason?: string } {
    const model = this.models.get(modelId);
    if (!model) return { valid: false, reason: 'Model not found in registry' };
    if (!model.governanceSignature || !model.attestationTimestamp) {
      return { valid: false, reason: 'No governance attestation signature found on model' };
    }

    try {
      const canonicalPayload = hashCanonicalJson({
        modelId: model.modelId,
        semanticVersion: model.semanticVersion,
        targetStatus: model.deploymentStatus,
        cryptographicDigest: model.cryptographicDigest,
        rocAuc: model.evaluationMetrics.rocAuc,
        timestamp: model.attestationTimestamp
      });

      const valid = crypto.verify(
        null,
        Buffer.from(canonicalPayload, 'utf8'),
        publicKeyPem,
        Buffer.from(model.governanceSignature, 'hex')
      );

      return { valid, reason: valid ? undefined : 'Attestation cryptographic verification failed' };
    } catch (err: any) {
      return { valid: false, reason: `Verification error: ${err.message}` };
    }
  }

  /**
   * Performs zero-downtime rollback to the designated previous stable model version
   */
  public rollback(modelId: string): ModelGovernanceMetadata {
    const failingModel = this.models.get(modelId);
    if (!failingModel) {
      throw new Error(`Model '${modelId}' not found`);
    }

    const rollbackTargetId = failingModel.rollbackPointer;
    if (!rollbackTargetId) {
      throw new Error(`No rollback pointer recorded for model '${modelId}'`);
    }

    const previousModel = this.models.get(rollbackTargetId);
    if (!previousModel) {
      throw new Error(`Target rollback model '${rollbackTargetId}' missing from registry`);
    }

    failingModel.deploymentStatus = 'ROLLED_BACK';
    previousModel.deploymentStatus = 'PRODUCTION';
    this.activeProductionModelId = rollbackTargetId;

    return previousModel;
  }

  public getModel(modelId: string): ModelGovernanceMetadata | undefined {
    return this.models.get(modelId);
  }

  public getActiveProductionModel(): ModelGovernanceMetadata | undefined {
    if (!this.activeProductionModelId) return undefined;
    return this.models.get(this.activeProductionModelId);
  }

  public listModels(): ModelGovernanceMetadata[] {
    return Array.from(this.models.values());
  }
}
