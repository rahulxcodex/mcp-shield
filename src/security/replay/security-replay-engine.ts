import { SecurityPipeline, MessageMetadata } from '../../core/pipeline/security-pipeline';
import { SecurityRuntime } from '../../core/runtime/security-runtime';
import { SecurityDecisionAction } from '../decision';

export interface ReplayInputEvent {
  eventId: string;
  timestamp: number;
  toolName: string;
  rawArgs: Record<string, unknown>;
  toolSchema?: Record<string, unknown>;
  originalDecision: {
    action: SecurityDecisionAction;
    riskScore: number;
    reason?: string;
  };
  originalLatencyUs?: number;
  groundTruthLabel?: 'BENIGN' | 'MALICIOUS';
}

export interface ReplayConfig {
  policyVersion?: string;
  detectorVersions?: Record<string, string>;
  modelVersion?: string;
  runtime?: SecurityRuntime;
}

export interface ReplayComparisonResult {
  eventId: string;
  toolName: string;
  oldAction: SecurityDecisionAction;
  newAction: SecurityDecisionAction;
  oldRiskScore: number;
  newRiskScore: number;
  actionChanged: boolean;
  riskDelta: number;
  latencyDeltaUs: number;
  changedEvidence: string[];
  attackFamiliesAffected: string[];
}

export interface ReplaySummaryReport {
  replayedAt: number;
  totalEvents: number;
  decisionsChanged: number;
  decisionsUnchanged: number;
  averageRiskDelta: number;
  averageLatencyDeltaUs: number;
  newBlocksCount: number;
  newAllowsCount: number;
  falsePositiveDelta: number;
  comparisons: ReplayComparisonResult[];
}

/**
 * Enterprise Security Replay Engine (Roadmap Section 7.6)
 * Safely evaluates historical security traffic against new detector heuristics,
 * updated policies, and governed models before production release.
 */
export class SecurityReplayEngine {
  private pipeline: SecurityPipeline;

  constructor(pipeline?: SecurityPipeline) {
    this.pipeline = pipeline || new SecurityPipeline();
  }

  /**
   * Replays recorded historical security events and computes decision diffs
   */
  public async replayEvents(
    events: ReplayInputEvent[],
    config: ReplayConfig = {}
  ): Promise<ReplaySummaryReport> {
    const comparisons: ReplayComparisonResult[] = [];
    let totalRiskDelta = 0;
    let totalLatencyDelta = 0;
    let decisionsChanged = 0;
    let newBlocksCount = 0;
    let newAllowsCount = 0;
    let falsePositiveDelta = 0;

    for (const evt of events) {
      const meta: MessageMetadata = {
        receivedAt: evt.timestamp || Date.now(),
        sessionId: `replay-${evt.eventId}`
      };

      const start = process.hrtime.bigint();

      const ctx = await this.pipeline.evaluate(
        {
          jsonrpc: '2.0',
          id: evt.eventId,
          method: 'tools/call',
          params: {
            name: evt.toolName,
            arguments: evt.rawArgs
          }
        },
        meta
      );

      const end = process.hrtime.bigint();
      const newLatencyUs = Number(end - start) / 1000;
      const oldLatencyUs = evt.originalLatencyUs || 200;
      const latencyDeltaUs = Number((newLatencyUs - oldLatencyUs).toFixed(1));

      const newAction: SecurityDecisionAction = ctx.decision?.action || 'ALLOW';
      const newRiskScore = ctx.risk.score;
      const oldAction = evt.originalDecision.action;
      const oldRiskScore = evt.originalDecision.riskScore;

      const actionChanged = newAction !== oldAction;
      const riskDelta = Number((newRiskScore - oldRiskScore).toFixed(3));

      if (actionChanged) {
        decisionsChanged += 1;
        if (newAction === 'BLOCK' && oldAction !== 'BLOCK') {
          newBlocksCount += 1;
          if (evt.groundTruthLabel === 'BENIGN') {
            falsePositiveDelta += 1; // Unwanted block on benign event
          }
        } else if (newAction === 'ALLOW' && oldAction === 'BLOCK') {
          newAllowsCount += 1;
          if (evt.groundTruthLabel === 'BENIGN') {
            falsePositiveDelta -= 1; // Resolved a previous false positive
          }
        }
      }

      totalRiskDelta += riskDelta;
      totalLatencyDelta += latencyDeltaUs;

      const changedEvidence = ctx.evidence.map((e) => `[${e.detectorId}] ${e.explanation || e.category}`);
      const attackFamiliesAffected = Array.from(new Set(ctx.evidence.map((e) => e.category)));

      comparisons.push({
        eventId: evt.eventId,
        toolName: evt.toolName,
        oldAction,
        newAction,
        oldRiskScore,
        newRiskScore,
        actionChanged,
        riskDelta,
        latencyDeltaUs,
        changedEvidence,
        attackFamiliesAffected
      });
    }

    const n = events.length || 1;
    return {
      replayedAt: Date.now(),
      totalEvents: events.length,
      decisionsChanged,
      decisionsUnchanged: events.length - decisionsChanged,
      averageRiskDelta: Number((totalRiskDelta / n).toFixed(3)),
      averageLatencyDeltaUs: Number((totalLatencyDelta / n).toFixed(1)),
      newBlocksCount,
      newAllowsCount,
      falsePositiveDelta,
      comparisons
    };
  }
}
