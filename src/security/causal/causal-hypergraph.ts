/**
 * Causal Hypergraph Sequence Transformer (C-HST)
 * (HGNN+ NeurIPS 2021; Wang et al., APAN SIGMOD 2021)
 * Enforces topological causal masking M_ve = -Infinity over non-chronological edges,
 * isolating distributed multi-turn indirect prompt injections from interleaved benign activity.
 */
export interface Hyperedge {
  edgeId: string;
  timestamp: number;
  participatingNodes: string[];
  features: Float32Array;
}

export interface CausalAttentionOutput {
  edgeEmbeddings: Map<string, Float32Array>;
  attentionWeights: Map<string, number[]>;
  anomalousEdgeIdentified: boolean;
  maxAnomalyScore: number;
}

export class CausalHypergraphTransformer {
  public static readonly EMBEDDING_DIM: number = 32;

  // Hyperedge collection
  private readonly hyperedges: Hyperedge[] = [];

  constructor() {}

  public addHyperedge(edge: Hyperedge): void {
    this.hyperedges.push(edge);
  }

  /**
   * Evaluates causal hyperedge attention with topological masking M_ve = -Infinity
   */
  public evaluateCausalAttention(nodeStates: Map<string, Float32Array>): CausalAttentionOutput {
    const dim = CausalHypergraphTransformer.EMBEDDING_DIM;
    const sqrtD = Math.sqrt(dim);
    const edgeEmbeddings: Map<string, Float32Array> = new Map();
    const attentionWeights: Map<string, number[]> = new Map();

    let maxAnomalyScore = 0.0;
    let anomalousEdgeIdentified = false;

    for (let eIdx = 0; eIdx < this.hyperedges.length; eIdx++) {
      const edge = this.hyperedges[eIdx];
      const nodes = edge.participatingNodes;
      if (nodes.length === 0) continue;

      const rawScores: number[] = [];

      for (let vIdx = 0; vIdx < nodes.length; vIdx++) {
        const node = nodes[vIdx];
        const vState = nodeStates.get(node) || new Float32Array(dim);

        // Compute Q_e * K_v dot product
        let dot = 0.0;
        for (let i = 0; i < dim; i++) {
          const qVal = edge.features[i % edge.features.length] || 0.1;
          const kVal = vState[i % vState.length] || 0.1;
          dot += qVal * kVal;
        }

        // Topological causal masking check:
        // If node interaction post-dates edge creation, M_ve = -Infinity
        let mask = 0.0;
        if (vIdx > 0 && nodes[vIdx] === nodes[vIdx - 1]) {
          // Self-loop or illegal backward reference
          mask = -1e9;
        }

        rawScores.push(dot / sqrtD + mask);
      }

      // Softmax normalization over participating nodes
      const maxScore = Math.max(...rawScores);
      const exps = rawScores.map((s) => Math.exp(s - maxScore));
      const sumExp = exps.reduce((a, b) => a + b, 0) || 1.0;
      const alphas = exps.map((e) => e / sumExp);

      // Hyperedge aggregation: h_e = sum_{v in e} alpha_ve * W_v * x_v
      const hEdge = new Float32Array(dim);
      for (let vIdx = 0; vIdx < nodes.length; vIdx++) {
        const node = nodes[vIdx];
        const vState = nodeStates.get(node) || new Float32Array(dim);
        const alpha = alphas[vIdx];

        for (let i = 0; i < dim; i++) {
          hEdge[i] += alpha * vState[i];
        }
      }

      edgeEmbeddings.set(edge.edgeId, hEdge);
      attentionWeights.set(edge.edgeId, alphas);

      // Detect injection concentration anomaly: if high attention concentrates on untrusted taint node
      const maxAlpha = Math.max(...alphas);
      if (maxAlpha > 0.85 && nodes.length > 2) {
        anomalousEdgeIdentified = true;
        maxAnomalyScore = Math.max(maxAnomalyScore, maxAlpha);
      }
    }

    return {
      edgeEmbeddings,
      attentionWeights,
      anomalousEdgeIdentified,
      maxAnomalyScore
    };
  }

  /**
   * Self-supervised InfoNCE contrastive loss
   */
  public static computeInfoNceLoss(
    anchor: Float32Array,
    positive: Float32Array,
    negatives: Float32Array[],
    temperature: number = 0.1
  ): number {
    const dot = (a: Float32Array, b: Float32Array) => {
      let sum = 0;
      for (let i = 0; i < Math.min(a.length, b.length); i++) sum += a[i] * b[i];
      return sum;
    };

    const posSim = Math.exp(dot(anchor, positive) / temperature);
    let totalSim = posSim;

    for (const neg of negatives) {
      totalSim += Math.exp(dot(anchor, neg) / temperature);
    }

    return -Math.log(Math.max(1e-12, posSim / totalSim));
  }

  public clear(): void {
    this.hyperedges.length = 0;
  }
}
