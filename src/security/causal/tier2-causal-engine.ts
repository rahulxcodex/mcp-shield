import { TgnMemoryEngine, InteractionEvent } from './tgn-memory';
import { MonotonicTaintField } from './monotonic-taint-field';
import { CausalHypergraphTransformer, Hyperedge } from './causal-hypergraph';
import { TruncatedBocpdEngine, BocpdResult } from './truncated-bocpd';
import { PersistentHomologyEngine, TopologicalSummary } from './persistent-homology';
import { PathIntegratedGradientsAttributor, AttributionCertificate } from './path-integrated-gradients';
import { AdaptiveConformalInference } from './adaptive-conformal-inference';
import { LmaxDisruptorRing } from '../../microkernel/ring-buffer/lmax-disruptor';

export interface Tier2CausalVerdict {
  transactionId: string;
  cleared: boolean;
  clearanceToken?: string;
  causalRiskScore: number;
  changepointDetected: boolean;
  topologicalCycleDetected: boolean;
  activeCycleNodes: string[];
  reasons: string[];
  calibratedThreshold: number;
}

export type FusedSecurityAction = 'MONITOR' | 'PROMPT' | 'SANDBOX' | 'QUARANTINE' | 'BLOCK';

export interface FusedDecisionResult {
  fusedScore: number;
  action: FusedSecurityAction;
  deterministicScore: number;
  tier1Prior: number;
  tier2Posterior: number;
  hardBlockTriggered: boolean;
}

/**
 * Tier 2: Asynchronous Deep Causal Engine (10-30ms Sidecar)
 * Coordinates:
 * - Continuous-Time Temporal Graph Network (TGN) with Fourier memory
 * - Monotonic Taint Field with Idempotent DLP Projection
 * - Causal Hypergraph Sequence Transformer (C-HST) with topological causal masking
 * - Truncated BOCPD Changepoint Detector (r_max = 128)
 * - Persistent Homology Betti-1 (beta_1) Topological Loop Filter
 * - Path-Integrated Gradients Attribution Engine (Ed25519 token signer)
 * - Adaptive Conformal Inference (ACI) Risk Controller
 */
export class Tier2CausalEngine {
  private readonly tgn: TgnMemoryEngine;
  private readonly taintField: MonotonicTaintField;
  private readonly chst: CausalHypergraphTransformer;
  private readonly bocpd: TruncatedBocpdEngine;
  private readonly tda: PersistentHomologyEngine;
  private readonly attributor: PathIntegratedGradientsAttributor;
  private readonly aci: AdaptiveConformalInference;

  constructor() {
    this.tgn = new TgnMemoryEngine();
    this.taintField = new MonotonicTaintField();
    this.chst = new CausalHypergraphTransformer();
    this.bocpd = new TruncatedBocpdEngine(50.0);
    this.tda = new PersistentHomologyEngine();
    this.attributor = new PathIntegratedGradientsAttributor(10);
    this.aci = new AdaptiveConformalInference(0.001, 0.005, 0.70);
  }

  /**
   * Evaluates a causal interaction and determines if clearance token should be emitted
   */
  public evaluateCausalAction(
    transactionId: string,
    sourceNode: string,
    targetNode: string,
    actionType: string,
    features: Float32Array,
    isTainted: boolean = false
  ): Tier2CausalVerdict {
    const reasons: string[] = [];
    const timestamp = Date.now();

    // 1. TGN Continuous-Time Interaction
    const event: InteractionEvent = {
      sourceNode,
      targetNode,
      timestamp,
      edgeFeature: features
    };
    const { sourceState, targetState } = this.tgn.processInteraction(event);

    // 2. Monotonic Taint Tracking
    if (isTainted) {
      this.taintField.setTaint(sourceNode, 1.0);
    }
    const currentTaint = this.taintField.propagateTaint(sourceNode, targetNode, 0.9, 0.1);

    // 3. Persistent Homology (Betti-1 Topological Cycle Check)
    this.tda.addEdge(sourceNode, targetNode);
    const homology: TopologicalSummary = this.tda.computeHomology();
    if (homology.persistentLoopDetected) {
      reasons.push(`Topological Betti-1 cycle detected (beta_1 = ${homology.beta1}) across: ${homology.activeCycleNodes.join(' -> ')}`);
    }

    // 4. Truncated BOCPD Changepoint Evaluation
    const bocpdScore = currentTaint * 0.5 + (homology.persistentLoopDetected ? 0.5 : 0.0);
    const bocpd: BocpdResult = this.bocpd.step(bocpdScore);
    if (bocpd.changepointDetected) {
      reasons.push(`Bayesian changepoint detected in tool trajectory (prob: ${bocpd.changepointProbability.toFixed(3)})`);
    }

    // 5. C-HST Hyperedge Attention
    const hyperedge: Hyperedge = {
      edgeId: `he_${transactionId}`,
      timestamp,
      participatingNodes: [sourceNode, targetNode],
      features
    };
    this.chst.addHyperedge(hyperedge);
    const nodeStates = new Map<string, Float32Array>([
      [sourceNode, sourceState],
      [targetNode, targetState]
    ]);
    const chstResult = this.chst.evaluateCausalAttention(nodeStates);
    if (chstResult.anomalousEdgeIdentified) {
      reasons.push(`C-HST causal injection attention anomaly (score: ${chstResult.maxAnomalyScore.toFixed(3)})`);
    }

    // 6. Aggregate Causal Risk Score
    let causalRisk = (currentTaint * 0.3) + (chstResult.maxAnomalyScore * 0.4);
    if (homology.persistentLoopDetected) causalRisk += 0.3;
    if (bocpd.changepointDetected) causalRisk += 0.2;
    causalRisk = Math.min(1.0, causalRisk);

    // 7. Adaptive Conformal Inference (ACI) update
    const aciResult = this.aci.update(causalRisk);
    const threshold = aciResult.currentThreshold;

    // 8. Path-Integrated Gradients Attribution & Ed25519 Clearance Token
    const baseline = new Float32Array(features.length);
    const weights = new Float32Array(features.length).fill(0.1);
    const cert: AttributionCertificate = this.attributor.issueClearanceToken(
      transactionId,
      features,
      baseline,
      weights,
      threshold
    );

    const cleared = cert.cleared && !homology.persistentLoopDetected && !chstResult.anomalousEdgeIdentified;
    let finalClearanceToken = cleared ? cert.clearanceToken : undefined;

    return {
      transactionId,
      cleared,
      clearanceToken: finalClearanceToken,
      causalRiskScore: causalRisk,
      changepointDetected: bocpd.changepointDetected,
      topologicalCycleDetected: homology.persistentLoopDetected,
      activeCycleNodes: homology.activeCycleNodes,
      reasons,
      calibratedThreshold: threshold
    };
  }

  /**
   * Consumes queued events from LMAX Disruptor ring buffer
   */
  public drainRingBuffer(ring: LmaxDisruptorRing, maxBatch: number = 32): number {
    let processed = 0;
    while (processed < maxBatch) {
      const evt = ring.dequeue();
      if (!evt) break;

      // Extract transaction features and evaluate
      const features = new Float32Array(32);
      features[0] = evt.payloadLength / 1024.0;
      this.evaluateCausalAction(evt.eventId, 'agent', 'tool', 'call', features);
      processed++;
    }
    return processed;
  }

  public getAttributor(): PathIntegratedGradientsAttributor {
    return this.attributor;
  }

  public getTaintField(): MonotonicTaintField {
    return this.taintField;
  }

  public getHomology(): PersistentHomologyEngine {
    return this.tda;
  }

  public getAci(): AdaptiveConformalInference {
    return this.aci;
  }

  /**
   * Unified Decision Fusion & Calibration Contract (Iteration 5, Section 1)
   * S_fused = max(S_det, 0.35 * z_T1 + 0.65 * p_hat_T2)
   */
  public static fuseDecision(
    sDet: number,
    zT1: number,
    pT2: number
  ): FusedDecisionResult {
    const hardBlockTriggered = sDet >= 1.0;
    const weightedMl = Math.max(pT2, 0.35 * zT1 + 0.65 * pT2);
    const fusedScore = Math.min(1.0, Math.max(sDet, weightedMl));

    let action: FusedSecurityAction;
    if (fusedScore >= 0.85 || hardBlockTriggered) {
      action = 'BLOCK';
    } else if (fusedScore >= 0.70) {
      action = 'QUARANTINE';
    } else if (fusedScore >= 0.45) {
      action = 'SANDBOX';
    } else if (fusedScore >= 0.20) {
      action = 'PROMPT';
    } else {
      action = 'MONITOR';
    }

    return {
      fusedScore,
      action,
      deterministicScore: sDet,
      tier1Prior: zT1,
      tier2Posterior: pT2,
      hardBlockTriggered
    };
  }
}
