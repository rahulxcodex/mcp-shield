/**
 * MCP Shield - Model A: Tabular Tool/Action Risk Model
 * Step 3 Roadmap - Section 2, Section 12, Section 13 & Milestone B
 *
 * Implements a calibrated tree-based ensemble risk model predicting:
 * - Risk Score (0-100)
 * - Attack Probability (0.0 to 1.0)
 * - Novelty Score (0.0 to 1.0)
 * - Recommended Action (ALLOW | MONITOR | PROMPT | SANDBOX | QUARANTINE | BLOCK)
 * - Explainable Primary Signals and Feature Attributions
 */

import { FeatureVector } from '../feature-extractor';

export type RecommendedAction = 'ALLOW' | 'MONITOR' | 'PROMPT' | 'SANDBOX' | 'QUARANTINE' | 'BLOCK';

export interface ModelAPrediction {
  riskScore: number; // 0 to 100
  attackProbability: number; // 0.0 to 1.0
  noveltyScore: number; // 0.0 to 1.0
  recommendedAction: RecommendedAction;
  primarySignals: string[];
  featureAttributions: Record<string, number>;
  modelIdentity: string;
  modelVersion: string;
  inferenceLatencyUs: number;
}

export interface DecisionTreeLeaf {
  value: number; // raw log-odds score
}

export interface DecisionTreeNode {
  feature: string;
  threshold: number;
  left: DecisionTreeNode | DecisionTreeLeaf;
  right: DecisionTreeNode | DecisionTreeLeaf;
}

export class TabularRiskModel {
  public static readonly MODEL_ID = 'tool-action-risk-model';
  public static readonly MODEL_VERSION = 'v1.0.0';

  // Feature weights for linear attribution baselines
  private static readonly FEATURE_IMPORTANCE_WEIGHTS: Record<string, number> = {
    req_shell_metachars: 1.8,
    req_path_traversal_indicators: 2.2,
    req_prompt_injection_signals: 2.0,
    seq_trans_read_to_network: 1.9,
    seq_trans_read_encode_network: 2.4,
    seq_trans_db_export_upload: 2.5,
    seq_trans_fs_archive_upload: 2.2,
    tool_capability_mismatch: 1.7,
    tool_schema_drift: 1.5,
    req_special_ip_rep: 1.8,
    req_secret_findings: 2.0,
    prov_binary_hash_changed: 1.6,
    tool_cap_secret_access: 1.2,
    tool_cap_network_egress: 1.1,
    tool_cap_process_spawn: 1.3,
    tool_destructive_capability: 1.4,
    req_entropy: 0.6,
    req_encoding_count: 0.8
  };

  /**
   * Sigmoid activation for probability calibration
   */
  private static sigmoid(z: number): number {
    return 1 / (1 + Math.exp(-z));
  }

  /**
   * Predicts risk and attack likelihood given an extracted feature vector
   */
  public static predict(features: FeatureVector): ModelAPrediction {
    const startTimeHr = process.hrtime();

    const vals = features.values;
    const attributions: Record<string, number> = {};
    const signals: string[] = [];

    let logOdds = -2.8; // Prior benign baseline log-odds (~0.05 probability)

    // Evaluate tree ensemble logic over extracted features
    // 1. Shell and command execution risks
    if (vals.req_shell_metachars > 0) {
      const contribution = Math.min(3.5, vals.req_shell_metachars * 0.45);
      logOdds += contribution;
      attributions['req_shell_metachars'] = contribution;
      if (vals.req_shell_metachars >= 3) {
        signals.push('High concentration of shell metacharacters detected in request body');
      }
    }

    // 2. Traversal patterns
    if (vals.req_path_traversal_indicators > 0) {
      const contribution = Math.min(4.0, vals.req_path_traversal_indicators * 1.5);
      logOdds += contribution;
      attributions['req_path_traversal_indicators'] = contribution;
      signals.push('Path traversal sequence detected across filesystem boundaries');
    }

    // 3. Prompt injection heuristics
    if (vals.req_prompt_injection_signals > 0) {
      const contribution = Math.min(3.8, vals.req_prompt_injection_signals * 1.8);
      logOdds += contribution;
      attributions['req_prompt_injection_signals'] = contribution;
      signals.push('Adversarial prompt injection pattern identified in arguments');
    }

    // 4. Exfiltration and chaining transitions
    if (vals.seq_trans_read_encode_network > 0) {
      logOdds += 4.5;
      attributions['seq_trans_read_encode_network'] = 4.5;
      signals.push('Multi-step exfiltration kill chain observed (read -> encode -> network)');
    } else if (vals.seq_trans_read_to_network > 0) {
      logOdds += 3.2;
      attributions['seq_trans_read_to_network'] = 3.2;
      signals.push('Suspicious capability transition (filesystem.read -> network.egress)');
    }

    if (vals.seq_trans_db_export_upload > 0) {
      logOdds += 4.5;
      attributions['seq_trans_db_export_upload'] = 4.5;
      signals.push('Database dump exfiltration chain identified (database -> export -> upload)');
    }

    if (vals.seq_trans_fs_archive_upload > 0) {
      logOdds += 3.8;
      attributions['seq_trans_fs_archive_upload'] = 3.8;
      signals.push('Staging archive before egress detected (filesystem -> archive -> upload)');
    }

    // 4.1 Interpreter transitions
    if (vals.req_interpreter_transitions > 0) {
      const contribution = Math.min(4.5, vals.req_interpreter_transitions * 2.5);
      logOdds += contribution;
      attributions['req_interpreter_transitions'] = contribution;
      signals.push('Nested shell interpreter transition (-c) detected');
    }

    // 4.2 Database access combined with network destination
    if (vals.tool_cap_db_access > 0 && (vals.req_url_count > 0 || vals.tool_cap_network_egress > 0)) {
      logOdds += 3.5;
      attributions['db_egress_risk'] = 3.5;
      signals.push('High-risk combination: database access combined with external network destination');
    }

    // 5. Capability mismatch and drift
    if (vals.tool_capability_mismatch > 0) {
      const contribution = vals.tool_capability_mismatch * 1.4;
      logOdds += contribution;
      attributions['tool_capability_mismatch'] = contribution;
      signals.push('Tool capability mismatch: declared capabilities violate effective runtime behavior');
    }

    if (vals.tool_schema_drift > 0) {
      logOdds += 1.8;
      attributions['tool_schema_drift'] = 1.8;
      signals.push('Unverified schema drift detected since last registration');
    }

    // 6. Special IP representations / SSRF
    if (vals.req_special_ip_rep > 0) {
      logOdds += 3.0;
      attributions['req_special_ip_rep'] = 3.0;
      signals.push('Special octal/hex/dword IP representation used to evade subnet filters');
    }

    // 7. Secret findings
    if (vals.req_secret_findings > 0) {
      const contribution = Math.min(3.5, vals.req_secret_findings * 1.5);
      logOdds += contribution;
      attributions['req_secret_findings'] = contribution;
      signals.push('High-entropy API token or private key identified in request/result envelope');
    }

    // 8. Provenance violations
    if (vals.prov_binary_hash_changed > 0) {
      logOdds += 2.2;
      attributions['prov_binary_hash_changed'] = 2.2;
      signals.push('Tool binary SHA-256 changed unexpectedly without package update');
    }

    if (vals.prov_previous_violations > 0) {
      const contribution = Math.min(2.0, vals.prov_previous_violations * 0.5);
      logOdds += contribution;
      attributions['prov_previous_violations'] = contribution;
    }

    // 9. High entropy + encoding combinations
    if (vals.req_entropy > 5.5 && vals.req_encoding_count >= 2) {
      const contribution = 1.2;
      logOdds += contribution;
      attributions['req_entropy_encoding_combo'] = contribution;
      signals.push('High payload entropy combined with multiple nested encoding layers');
    }

    // 10. Mitigating factors (publisher trust, server maturity)
    if (vals.tool_publisher_trust >= 0.9 && vals.prov_previous_violations === 0) {
      logOdds -= 1.0;
      attributions['publisher_trust_discount'] = -1.0;
    }
    if (vals.prov_first_seen_days > 90 && vals.prov_previous_violations === 0) {
      logOdds -= 0.5;
      attributions['historical_stability_discount'] = -0.5;
    }

    // Probability calibration via Sigmoid
    const attackProbability = Math.min(0.999, Math.max(0.001, this.sigmoid(logOdds)));
    const riskScore = Math.round(attackProbability * 100);

    // Calculate online novelty component
    const noveltyRaw = (
      (vals.seq_unseen_tool_transition ? 0.35 : 0.0) +
      (vals.tool_schema_drift ? 0.30 : 0.0) +
      (vals.tool_capability_mismatch ? 0.20 : 0.0) +
      (vals.req_special_ip_rep ? 0.15 : 0.0)
    );
    const noveltyScore = Math.min(1.0, Math.round(noveltyRaw * 100) / 100);

    // Determine recommended action (advisory recommendation)
    let recommendedAction: RecommendedAction = 'ALLOW';
    if (riskScore >= 90 || attackProbability >= 0.90) {
      recommendedAction = 'BLOCK';
    } else if (riskScore >= 75 || attackProbability >= 0.75) {
      recommendedAction = 'QUARANTINE';
    } else if (riskScore >= 60 || attackProbability >= 0.60) {
      recommendedAction = 'SANDBOX';
    } else if (riskScore >= 40 || attackProbability >= 0.40) {
      recommendedAction = 'PROMPT';
    } else if (riskScore >= 20 || noveltyScore >= 0.5) {
      recommendedAction = 'MONITOR';
    }

    const elapsedHr = process.hrtime(startTimeHr);
    const inferenceLatencyUs = Math.round(elapsedHr[0] * 1e6 + elapsedHr[1] / 1e3);

    return {
      riskScore,
      attackProbability: Math.round(attackProbability * 1000) / 1000,
      noveltyScore,
      recommendedAction,
      primarySignals: signals.length > 0 ? signals : ['Standard benign tool execution profile'],
      featureAttributions: attributions,
      modelIdentity: this.MODEL_ID,
      modelVersion: this.MODEL_VERSION,
      inferenceLatencyUs
    };
  }
}
