/**
 * MCP Shield - Privacy-Preserving Telemetry Engine
 * Step 3 Roadmap - Section 9 & Milestone E
 *
 * Transmits extracted security features, capability vectors, and schema digests
 * rather than raw user payloads. Supports 4 enterprise deployment modes:
 * - cloud-intel: Full anonymized feature vector + detector signals
 * - private-telemetry: Aggregated counters and high-level risk scores only
 * - self-hosted: Local logging only, zero outbound egress
 * - air-gapped: Complete network isolation, strictly local cryptographic audit
 */

import { FeatureVector } from './feature-extractor';
import { ModelAPrediction } from './models/tabular-risk-model';
import { SecurityEvidence } from '../evidence';
import { hashCanonicalJson } from '../canonical-json';

export type DeploymentMode = 'cloud-intel' | 'private-telemetry' | 'self-hosted' | 'air-gapped';

export interface PrivacyTelemetryPayload {
  deploymentMode: DeploymentMode;
  timestamp: number;
  eventId: string;
  serverIdentityHash: string;
  schemaFingerprint: string;
  capabilityVector: string[];
  destinationCategory?: 'internal' | 'cloud_metadata' | 'external_internet' | 'loopback';
  riskScore: number;
  attackProbability: number;
  noveltyScore: number;
  recommendedAction: string;
  detectorCategories: string[];
  featureDigest?: string; // HMAC/SHA256 of feature vector
  rawBodyIncluded: boolean; // Always false in privacy mode
}

export class PrivacyTelemetryEngine {
  private mode: DeploymentMode;
  private serverIdentity: string;

  constructor(mode: DeploymentMode = 'cloud-intel', serverIdentity: string = 'mcp-server-default') {
    this.mode = mode;
    this.serverIdentity = serverIdentity;
  }

  public getMode(): DeploymentMode {
    return this.mode;
  }

  public setMode(mode: DeploymentMode): void {
    this.mode = mode;
  }

  /**
   * Sanitizes and packages telemetry according to active enterprise deployment mode
   */
  public packageTelemetry(params: {
    toolName: string;
    schema: any;
    capabilities: string[];
    features: FeatureVector;
    prediction: ModelAPrediction;
    evidence: SecurityEvidence[];
    destinationCategory?: 'internal' | 'cloud_metadata' | 'external_internet' | 'loopback';
  }): PrivacyTelemetryPayload | null {
    // Air-gapped and self-hosted never transmit outbound telemetry
    if (this.mode === 'air-gapped' || this.mode === 'self-hosted') {
      return null;
    }

    const { toolName, schema, capabilities, features, prediction, evidence, destinationCategory } = params;
    const serverIdentityHash = hashCanonicalJson({ id: this.serverIdentity }).slice(0, 16);
    const schemaFingerprint = hashCanonicalJson(schema || {}).slice(0, 16);
    const eventId = `TEL-${hashCanonicalJson({ toolName, ts: Date.now() }).slice(0, 12)}`;

    if (this.mode === 'private-telemetry') {
      // Minimal aggregated risk envelope, zero feature specifics
      return {
        deploymentMode: 'private-telemetry',
        timestamp: Date.now(),
        eventId,
        serverIdentityHash,
        schemaFingerprint,
        capabilityVector: [...capabilities],
        destinationCategory,
        riskScore: prediction.riskScore,
        attackProbability: prediction.attackProbability,
        noveltyScore: prediction.noveltyScore,
        recommendedAction: prediction.recommendedAction,
        detectorCategories: Array.from(new Set(evidence.map(e => e.category))),
        rawBodyIncluded: false
      };
    }

    // Cloud intelligence mode: privacy-preserving feature vector digest and signals
    const featureDigest = hashCanonicalJson(features.values);

    return {
      deploymentMode: 'cloud-intel',
      timestamp: Date.now(),
      eventId,
      serverIdentityHash,
      schemaFingerprint,
      capabilityVector: [...capabilities],
      destinationCategory,
      riskScore: prediction.riskScore,
      attackProbability: prediction.attackProbability,
      noveltyScore: prediction.noveltyScore,
      recommendedAction: prediction.recommendedAction,
      detectorCategories: Array.from(new Set(evidence.map(e => e.category))),
      featureDigest,
      rawBodyIncluded: false
    };
  }
}
