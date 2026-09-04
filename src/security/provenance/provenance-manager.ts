import * as crypto from 'crypto';
import { ProvenanceDecision } from '../decision';

export interface SchemaHistoryEntry {
  version: string;
  hash: string;
  timestamp: number;
}

export interface PolicyHistoryEntry {
  policyId: string;
  modifiedAt: number;
  changeSummary: string;
}

export interface AuthoritativeProvenanceRecord {
  packageIdentity: string;
  publisherIdentity: string;
  binaryDigest: string;
  signature?: string;
  signatureVerified: boolean;
  firstSeenTimestamp: number;
  lastSeenTimestamp: number;
  deploymentCount: number;
  schemaHistory: SchemaHistoryEntry[];
  policyHistory: PolicyHistoryEntry[];
  incidentCount: number;
  trustScore: number; // 0.0 to 1.0
  evidence: string[];
}

export class ProvenanceManager {
  private records: Map<string, AuthoritativeProvenanceRecord> = new Map();

  /**
   * Registers or updates a package's authoritative provenance profile
   */
  public registerOrUpdateProvenance(
    entry: {
      packageIdentity: string;
      publisherIdentity: string;
      binaryDigest: string;
      signature?: string;
      signatureVerified?: boolean;
      initialTrustScore?: number;
      schemaHash?: string;
    }
  ): AuthoritativeProvenanceRecord {
    const existing = this.records.get(entry.packageIdentity);
    const now = Date.now();

    if (existing) {
      existing.lastSeenTimestamp = now;
      existing.deploymentCount += 1;
      if (entry.signatureVerified !== undefined) {
        existing.signatureVerified = entry.signatureVerified;
      }
      if (entry.schemaHash && !existing.schemaHistory.some((s) => s.hash === entry.schemaHash)) {
        existing.schemaHistory.push({
          version: `v${existing.schemaHistory.length + 1}`,
          hash: entry.schemaHash,
          timestamp: now
        });
      }
      return existing;
    }

    const record: AuthoritativeProvenanceRecord = {
      packageIdentity: entry.packageIdentity,
      publisherIdentity: entry.publisherIdentity,
      binaryDigest: entry.binaryDigest,
      signature: entry.signature,
      signatureVerified: entry.signatureVerified ?? false,
      firstSeenTimestamp: now,
      lastSeenTimestamp: now,
      deploymentCount: 1,
      schemaHistory: entry.schemaHash
        ? [{ version: 'v1', hash: entry.schemaHash, timestamp: now }]
        : [],
      policyHistory: [],
      incidentCount: 0,
      trustScore: entry.initialTrustScore ?? (entry.signatureVerified ? 0.9 : 0.6),
      evidence: [
        `First seen at ${new Date(now).toISOString()}`,
        `Publisher: ${entry.publisherIdentity}`
      ]
    };

    this.records.set(entry.packageIdentity, record);
    return record;
  }

  /**
   * Records a security incident associated with this package
   */
  public recordIncident(packageIdentity: string, incidentSummary: string): void {
    const record = this.records.get(packageIdentity);
    if (record) {
      record.incidentCount += 1;
      record.trustScore = Math.max(0.0, Number((record.trustScore - 0.25).toFixed(2)));
      record.evidence.push(`Incident logged at ${new Date().toISOString()}: ${incidentSummary}`);
    }
  }

  /**
   * Evaluates live execution provenance against authoritative record
   */
  public evaluateProvenance(
    packageIdentity: string,
    liveBinaryDigest?: string,
    liveSchemaDigest?: string
  ): ProvenanceDecision {
    const record = this.records.get(packageIdentity);
    const notes: string[] = [];

    if (!record) {
      return {
        packageIdentity,
        publisherIdentity: 'UNKNOWN',
        binaryHashVerified: false,
        signatureVerified: false,
        trustScore: 0.2,
        anomalyDetected: true,
        notes: ['Package not found in authoritative provenance registry. Unverified first-time execution.']
      };
    }

    let anomalyDetected = false;

    // 1. Binary Digest verification
    let binaryHashVerified = true;
    if (liveBinaryDigest) {
      if (liveBinaryDigest !== record.binaryDigest) {
        binaryHashVerified = false;
        anomalyDetected = true;
        notes.push(
          `Binary digest mismatch: Expected '${record.binaryDigest.substring(0, 12)}...', observed '${liveBinaryDigest.substring(0, 12)}...'`
        );
      }
    }

    // 2. Schema Drift check
    if (liveSchemaDigest && record.schemaHistory.length > 0) {
      const latestKnownSchema = record.schemaHistory[record.schemaHistory.length - 1];
      if (latestKnownSchema.hash !== liveSchemaDigest) {
        anomalyDetected = true;
        notes.push(
          `Live schema digest '${liveSchemaDigest.substring(0, 12)}...' differs from registered schema '${latestKnownSchema.hash.substring(0, 12)}...'`
        );
      }
    }

    // 3. Incident check
    if (record.incidentCount > 0) {
      notes.push(`Package has ${record.incidentCount} recorded security incidents.`);
    }

    // 4. Age calculation
    const ageDays = Math.floor((Date.now() - record.firstSeenTimestamp) / (1000 * 60 * 60 * 24));
    if (ageDays < 7) {
      notes.push(`Package is newly introduced (< 7 days old: ${ageDays} days).`);
    }

    const calculatedTrust = anomalyDetected
      ? Math.min(record.trustScore, 0.3)
      : record.trustScore;

    return {
      packageIdentity: record.packageIdentity,
      publisherIdentity: record.publisherIdentity,
      binaryHashVerified,
      signatureVerified: record.signatureVerified,
      trustScore: calculatedTrust,
      anomalyDetected,
      notes
    };
  }

  public getRecord(packageIdentity: string): AuthoritativeProvenanceRecord | undefined {
    return this.records.get(packageIdentity);
  }
}
