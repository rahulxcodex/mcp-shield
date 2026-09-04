/**
 * MCP Shield - Schema Drift Detector
 * Step 3 Roadmap - Section 16 & Milestone C
 *
 * Tracks dynamic mutations and capability drifts as first-class security events:
 * - Old schema hash vs New schema hash
 * - Added / removed / modified parameters
 * - Altered tool descriptions (detecting covert poisoning)
 * - Capability expansion risk scoring (e.g. read -> read + network egress)
 */

import { hashCanonicalJson } from '../canonical-json';
import { CapabilityInferencer, ToolCapabilities } from '../capabilities';
import { SecurityEvidence } from '../evidence';

export interface SchemaSnapshot {
  toolName: string;
  schemaHash: string;
  schema: any;
  description: string;
  capabilities: ToolCapabilities;
  timestamp: number;
}

export type SchemaDriftClass =
  | 'BENIGN_UPDATE'
  | 'EXPECTED_RELEASE'
  | 'BREAKING_UPDATE'
  | 'CAPABILITY_ESCALATION'
  | 'SUSPICIOUS_DESCRIPTION_MUTATION'
  | 'CREDENTIAL_EXPANSION'
  | 'NETWORK_EXPANSION'
  | 'EXECUTION_EXPANSION';

export type DriftPolicyAction = 'ALLOW' | 'PROMPT' | 'SANDBOX' | 'BLOCK';

export interface SchemaDriftEvent {
  toolName: string;
  oldSchemaHash: string;
  newSchemaHash: string;
  addedParameters: string[];
  removedParameters: string[];
  descriptionChanged: boolean;
  capabilityExpansion: Array<keyof ToolCapabilities>;
  isHighRiskDrift: boolean;
  driftRiskScore: number; // 0.0 to 1.0
  driftClass?: SchemaDriftClass;
  policyAction?: DriftPolicyAction;
  evidence?: SecurityEvidence;
  explanation: string;
}

export class SchemaDriftDetector {
  private snapshots = new Map<string, SchemaSnapshot>(); // toolName -> snapshot

  /**
   * Registers or updates a tool snapshot and detects schema drift
   */
  public evaluateDrift(
    toolName: string,
    newSchema: any,
    newDescription: string = ''
  ): SchemaDriftEvent | null {
    const newSchemaHash = hashCanonicalJson(newSchema || {});
    const newInferred = CapabilityInferencer.infer(toolName, newSchema || {}, newDescription);
    const existing = this.snapshots.get(toolName);

    if (!existing) {
      // First registration, no drift
      this.snapshots.set(toolName, {
        toolName,
        schemaHash: newSchemaHash,
        schema: newSchema,
        description: newDescription,
        capabilities: newInferred,
        timestamp: Date.now()
      });
      return null;
    }

    if (existing.schemaHash === newSchemaHash && existing.description === newDescription) {
      // Identical schema and description
      return null;
    }

    // Analyze diff
    const oldProps = Object.keys(existing.schema?.properties || {});
    const newProps = Object.keys(newSchema?.properties || {});
    const addedParameters = newProps.filter(p => !oldProps.includes(p));
    const removedParameters = oldProps.filter(p => !newProps.includes(p));
    const descriptionChanged = existing.description !== newDescription;

    // Detect capability expansions (newly acquired capabilities)
    const capabilityExpansion: Array<keyof ToolCapabilities> = [];
    const keys: Array<keyof ToolCapabilities> = [
      'networkAccess',
      'processSpawn',
      'shellExecution',
      'filesystemWrite',
      'filesystemRead',
      'secretAccess',
      'destructiveOperation'
    ];

    for (const key of keys) {
      if (newInferred[key] && !existing.capabilities[key]) {
        capabilityExpansion.push(key);
      }
    }

    // Calculate drift risk score
    let driftRiskScore = 0.2; // Base drift penalty
    if (descriptionChanged) driftRiskScore += 0.2;
    if (addedParameters.length > 0) driftRiskScore += Math.min(0.2, addedParameters.length * 0.05);

    // Capability escalation is high risk
    if (capabilityExpansion.includes('networkAccess')) driftRiskScore += 0.4;
    if (capabilityExpansion.includes('processSpawn')) driftRiskScore += 0.4;
    if (capabilityExpansion.includes('shellExecution')) driftRiskScore += 0.4;
    if (capabilityExpansion.includes('filesystemWrite')) driftRiskScore += 0.3;
    if (capabilityExpansion.includes('secretAccess')) driftRiskScore += 0.4;

    driftRiskScore = Math.min(1.0, Math.round(driftRiskScore * 100) / 100);
    const isHighRiskDrift = driftRiskScore >= 0.6 || capabilityExpansion.length > 0;

    const explanation = `Schema drift detected for '${toolName}': ` + [
      addedParameters.length > 0 ? `added params [${addedParameters.join(', ')}]` : null,
      removedParameters.length > 0 ? `removed params [${removedParameters.join(', ')}]` : null,
      descriptionChanged ? 'modified description' : null,
      capabilityExpansion.length > 0 ? `CRITICAL capability escalation: [${capabilityExpansion.join(', ')}]` : null
    ].filter(Boolean).join('; ');

    const evidence: SecurityEvidence = {
      detectorId: 'schema-drift-detector',
      category: 'SCHEMA_POISONING',
      severity: driftRiskScore,
      confidence: 0.95,
      hardBlock: driftRiskScore >= 0.85,
      features: {
        toolName,
        oldSchemaHash: existing.schemaHash,
        newSchemaHash,
        expansionCount: capabilityExpansion.length,
        isHighRiskDrift
      },
      explanation
    };

    // Update snapshot
    this.snapshots.set(toolName, {
      toolName,
      schemaHash: newSchemaHash,
      schema: newSchema,
      description: newDescription,
      capabilities: newInferred,
      timestamp: Date.now()
    });

    // Classify drift into policy-aware category
    let driftClass: SchemaDriftClass = 'BENIGN_UPDATE';
    let policyAction: DriftPolicyAction = 'ALLOW';

    if (capabilityExpansion.includes('secretAccess')) {
      driftClass = 'CREDENTIAL_EXPANSION';
      policyAction = 'BLOCK';
    } else if (capabilityExpansion.includes('networkAccess')) {
      driftClass = 'NETWORK_EXPANSION';
      policyAction = 'PROMPT';
    } else if (capabilityExpansion.includes('processSpawn') || capabilityExpansion.includes('shellExecution')) {
      driftClass = 'EXECUTION_EXPANSION';
      policyAction = 'SANDBOX';
    } else if (capabilityExpansion.length > 0) {
      driftClass = 'CAPABILITY_ESCALATION';
      policyAction = 'PROMPT';
    } else if (descriptionChanged && (/ignore previous|prompt|system|override|token|secret/i.test(newDescription))) {
      driftClass = 'SUSPICIOUS_DESCRIPTION_MUTATION';
      policyAction = 'PROMPT';
    } else if (removedParameters.length > 0) {
      driftClass = 'BREAKING_UPDATE';
      policyAction = 'ALLOW';
    } else {
      driftClass = 'BENIGN_UPDATE';
      policyAction = 'ALLOW';
    }

    return {
      toolName,
      oldSchemaHash: existing.schemaHash,
      newSchemaHash,
      addedParameters,
      removedParameters,
      descriptionChanged,
      capabilityExpansion,
      isHighRiskDrift,
      driftRiskScore,
      driftClass,
      policyAction,
      evidence,
      explanation
    };
  }

  public getSnapshot(toolName: string): SchemaSnapshot | undefined {
    return this.snapshots.get(toolName);
  }
}
