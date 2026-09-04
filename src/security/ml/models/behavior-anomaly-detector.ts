/**
 * MCP Shield - Model C: Behavioral Anomaly Detection
 * Step 3 Roadmap - Section 4, Section 13 & Milestone C
 *
 * Models runtime behavior sequences across:
 * - Agent / Server / Tool / Capability / Resource / Destination transitions
 *
 * Detects:
 * - New sequences (unseen transitions with low prior probability)
 * - New capabilities (capabilities not observed in baseline)
 * - New destinations (unseen egress destinations)
 * - Privilege transitions (low-privilege -> high-privilege leaps)
 */

import { SecurityEvidence } from '../../evidence';

export type AnomalyType =
  | 'NEW_SEQUENCE'
  | 'NEW_CAPABILITY'
  | 'NEW_DESTINATION'
  | 'PRIVILEGE_TRANSITION'
  | 'BURST_VELOCITY';

export interface BehavioralDeviation {
  type: AnomalyType;
  description: string;
  severity: number; // 0.0 to 1.0
  observed: string;
  baselineContext?: string;
}

export interface AnomalyDetectionResult {
  isAnomalous: boolean;
  anomalyScore: number; // 0.0 to 1.0
  deviations: BehavioralDeviation[];
  primarySignals: string[];
  evidence?: SecurityEvidence;
  inferenceLatencyUs: number;
}

export interface TransitionProfile {
  knownTools: Set<string>;
  knownTransitions: Map<string, number>; // "toolA->toolB" -> count
  knownCapabilities: Set<string>;
  knownDestinations: Set<string>;
  highPrivilegeTools: Set<string>;
}

export class BehaviorAnomalyDetector {
  public static readonly MODEL_ID = 'behavioral-anomaly-detector';
  public static readonly MODEL_VERSION = 'v1.0.0';

  private profile: TransitionProfile;

  constructor(initialBaseline?: {
    knownTools?: string[];
    knownTransitions?: Array<[string, string]>;
    knownCapabilities?: string[];
    knownDestinations?: string[];
    highPrivilegeTools?: string[];
  }) {
    this.profile = {
      knownTools: new Set(initialBaseline?.knownTools || ['git_status', 'read_file', 'list_dir', 'search_code']),
      knownTransitions: new Map(),
      knownCapabilities: new Set(initialBaseline?.knownCapabilities || ['filesystemRead']),
      knownDestinations: new Set(initialBaseline?.knownDestinations || ['localhost', '127.0.0.1']),
      highPrivilegeTools: new Set(initialBaseline?.highPrivilegeTools || ['bash', 'run_command', 'eval', 'exec', 'container_spawn', 'vault_read'])
    };

    if (initialBaseline?.knownTransitions) {
      for (const [from, to] of initialBaseline.knownTransitions) {
        this.profile.knownTransitions.set(`${from}->${to}`, 10);
      }
    }
  }

  /**
   * Records a normal transition to update baseline in-memory
   */
  public recordTransition(fromTool: string, toTool: string, capabilities: string[] = [], destination?: string): void {
    this.profile.knownTools.add(fromTool);
    this.profile.knownTools.add(toTool);
    const key = `${fromTool}->${toTool}`;
    this.profile.knownTransitions.set(key, (this.profile.knownTransitions.get(key) || 0) + 1);

    for (const cap of capabilities) {
      this.profile.knownCapabilities.add(cap);
    }
    if (destination) {
      this.profile.knownDestinations.add(destination);
    }
  }

  /**
   * Evaluates an action against the learned behavioral profile
   */
  public evaluateAction(params: {
    lastTool?: string;
    currentTool: string;
    currentCapabilities: string[];
    destination?: string;
    toolHistory?: string[];
  }): AnomalyDetectionResult {
    const startTimeHr = process.hrtime();
    const { lastTool, currentTool, currentCapabilities, destination } = params;

    const deviations: BehavioralDeviation[] = [];
    const signals: string[] = [];

    // 1. Tool Novelty & Sequence Check
    if (lastTool && lastTool !== currentTool) {
      const transKey = `${lastTool}->${currentTool}`;
      const count = this.profile.knownTransitions.get(transKey) || 0;
      if (count === 0 && this.profile.knownTransitions.size > 5) {
        deviations.push({
          type: 'NEW_SEQUENCE',
          description: `Unseen tool transition: '${lastTool}' -> '${currentTool}'`,
          severity: 0.65,
          observed: transKey,
          baselineContext: 'Zero prior occurrences in learned baseline'
        });
        signals.push(`Unseen tool sequence transition: ${transKey}`);
      }
    }

    // 2. Capability Jumps
    for (const cap of currentCapabilities) {
      if (!this.profile.knownCapabilities.has(cap) && this.profile.knownCapabilities.size > 0) {
        deviations.push({
          type: 'NEW_CAPABILITY',
          description: `Acquired unobserved capability: '${cap}'`,
          severity: 0.75,
          observed: cap,
          baselineContext: `Allowed baseline capabilities: [${Array.from(this.profile.knownCapabilities).join(', ')}]`
        });
        signals.push(`New unobserved capability exercised: ${cap}`);
      }
    }

    // 3. Privilege Transitions
    if (lastTool && !this.profile.highPrivilegeTools.has(lastTool) && this.profile.highPrivilegeTools.has(currentTool)) {
      deviations.push({
        type: 'PRIVILEGE_TRANSITION',
        description: `Sudden leap to high-privilege execution tool '${currentTool}' from unprivileged '${lastTool}'`,
        severity: 0.70,
        observed: `${lastTool} -> ${currentTool}`
      });
      signals.push(`Sudden privilege escalation leap from ${lastTool} to ${currentTool}`);
    }

    // 4. Destination Novelty
    if (destination && !this.profile.knownDestinations.has(destination) && this.profile.knownDestinations.size > 0) {
      deviations.push({
        type: 'NEW_DESTINATION',
        description: `Egress to unknown destination host: '${destination}'`,
        severity: 0.75,
        observed: destination
      });
      signals.push(`Egress to novel external destination: ${destination}`);
    }

    // Aggregate anomaly score
    let anomalyScore = 0.0;
    if (deviations.length > 0) {
      const maxSev = Math.max(...deviations.map(d => d.severity));
      const bonus = Math.min(0.25, (deviations.length - 1) * 0.1);
      anomalyScore = Math.min(1.0, maxSev + bonus);
    }

    const isAnomalous = anomalyScore >= 0.60;

    const elapsedHr = process.hrtime(startTimeHr);
    const latencyUs = Math.round(elapsedHr[0] * 1e6 + elapsedHr[1] / 1e3);

    let evidence: SecurityEvidence | undefined;
    if (isAnomalous) {
      evidence = {
        detectorId: BehaviorAnomalyDetector.MODEL_ID,
        category: 'ANOMALOUS_BEHAVIOR',
        severity: anomalyScore,
        confidence: 0.85,
        hardBlock: false, // Model C increases suspicion, never hard blocks alone
        features: {
          deviationCount: deviations.length,
          anomalyScore,
          currentTool
        },
        explanation: `Model C Behavioral Anomaly detected: ${signals.join('; ')}`
      };
    }

    return {
      isAnomalous,
      anomalyScore: Math.round(anomalyScore * 100) / 100,
      deviations,
      primarySignals: signals.length > 0 ? signals : ['Action conforms to established baseline'],
      evidence,
      inferenceLatencyUs: latencyUs
    };
  }
}
