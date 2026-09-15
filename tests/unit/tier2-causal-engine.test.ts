import {
  TgnMemoryEngine,
  MonotonicTaintField,
  CausalHypergraphTransformer,
  TruncatedBocpdEngine,
  PersistentHomologyEngine,
  PathIntegratedGradientsAttributor,
  AdaptiveConformalInference,
  Tier2CausalEngine,
  LmaxDisruptorRing
} from '../../src';

describe('Tier 2 Asynchronous Deep Causal Engine Suite (Blueprint Sections 3, 4, 5)', () => {
  describe('TgnMemoryEngine (Continuous-Time Fourier Memory)', () => {
    it('computes continuous-time harmonic Fourier encodings', () => {
      const tgn = new TgnMemoryEngine();
      const enc1 = tgn.computeTimeEncoding(10);
      const enc2 = tgn.computeTimeEncoding(100);

      expect(enc1.length).toBe(TgnMemoryEngine.TIME_ENC_DIM);
      expect(enc2.length).toBe(TgnMemoryEngine.TIME_ENC_DIM);
      expect(enc1[0]).not.toBe(enc2[0]);
    });

    it('updates node memory vectors via GRU state transitions', () => {
      const tgn = new TgnMemoryEngine();
      const event = {
        sourceNode: 'agent_main',
        targetNode: 'tool_shell',
        timestamp: 1000,
        edgeFeature: new Float32Array(8).fill(0.5)
      };

      const { sourceState, targetState } = tgn.processInteraction(event);
      expect(sourceState.length).toBe(TgnMemoryEngine.MEMORY_DIM);
      expect(targetState.length).toBe(TgnMemoryEngine.MEMORY_DIM);
    });
  });

  describe('MonotonicTaintField (Max-Algebra & Idempotent DLP)', () => {
    it('satisfies monotonicity invariant tau_v(t) >= tau_u(t^-) * w_uv', () => {
      const field = new MonotonicTaintField();
      field.setTaint('vault_node', 0.8);

      const targetTaint = field.propagateTaint('vault_node', 'staging_node', 0.9, 0.0);
      expect(targetTaint).toBeGreaterThanOrEqual(0.8 * 0.9);
      expect(field.getTaint('staging_node')).toBe(targetTaint);
    });

    it('satisfies idempotent projection Pi_DLP o Pi_DLP = Pi_DLP', () => {
      const field = new MonotonicTaintField();
      field.setTaint('output_node', 0.95);

      const attestation = field.createDlpAttestation('output_node');
      const firstProjection = field.projectDlp('output_node', attestation);
      expect(firstProjection).toBe(0.0);

      // Idempotency: second projection yields identical state (0.0)
      const secondProjection = field.projectDlp('output_node', attestation);
      expect(secondProjection).toBe(0.0);
    });
  });

  describe('CausalHypergraphTransformer (C-HST Attention & InfoNCE)', () => {
    it('evaluates causal hyperedge attention with topological masking', () => {
      const chst = new CausalHypergraphTransformer();
      chst.addHyperedge({
        edgeId: 'edge_1',
        timestamp: 100,
        participatingNodes: ['agent', 'tool_a', 'sink'],
        features: new Float32Array(32).fill(0.2)
      });

      const nodeStates = new Map([
        ['agent', new Float32Array(32).fill(0.1)],
        ['tool_a', new Float32Array(32).fill(0.1)],
        ['sink', new Float32Array(32).fill(0.1)]
      ]);

      const result = chst.evaluateCausalAttention(nodeStates);
      expect(result.edgeEmbeddings.has('edge_1')).toBe(true);
      expect(result.attentionWeights.has('edge_1')).toBe(true);
    });

    it('computes self-supervised InfoNCE loss', () => {
      const anchor = new Float32Array([1.0, 0.0]);
      const positive = new Float32Array([0.9, 0.1]);
      const negatives = [new Float32Array([0.0, 1.0]), new Float32Array([-1.0, 0.0])];

      const loss = CausalHypergraphTransformer.computeInfoNceLoss(anchor, positive, negatives);
      expect(loss).toBeGreaterThan(0.0);
    });
  });

  describe('TruncatedBocpdEngine (r_max = 128 Memory Bound)', () => {
    it('detects online changepoints when variance shifts', () => {
      const bocpd = new TruncatedBocpdEngine(20.0);

      // Steady state
      for (let i = 0; i < 30; i++) {
        bocpd.step(0.1);
      }

      // Sudden abrupt shift
      const result = bocpd.step(5.0);
      expect(result.changepointDetected).toBe(true);
      expect(result.changepointProbability).toBeGreaterThan(0.40);
    });
  });

  describe('PersistentHomologyEngine (Betti-1 Topological Loop Detection)', () => {
    it('computes beta_1 = 0 for benign acyclic DAG execution', () => {
      const tda = new PersistentHomologyEngine();
      // Linear tree: Agent -> Tool1 -> Tool2 -> Output
      tda.addEdge('agent', 'tool1');
      tda.addEdge('tool1', 'tool2');
      tda.addEdge('tool2', 'output');

      const summary = tda.computeHomology();
      expect(summary.beta1).toBe(0);
      expect(summary.persistentLoopDetected).toBe(false);
    });

    it('detects persistent 1D cycle (beta_1 >= 1) in cyclic exfiltration chain', () => {
      const tda = new PersistentHomologyEngine();
      // 4-node cycle without triangulating chords: A -> B -> C -> D -> A
      tda.addEdge('nodeA', 'nodeB');
      tda.addEdge('nodeB', 'nodeC');
      tda.addEdge('nodeC', 'nodeD');
      tda.addEdge('nodeD', 'nodeA');

      const summary = tda.computeHomology();
      expect(summary.beta1).toBeGreaterThanOrEqual(1);
      expect(summary.persistentLoopDetected).toBe(true);
      expect(summary.activeCycleNodes.length).toBeGreaterThan(0);
    });
  });

  describe('PathIntegratedGradientsAttributor & ACI', () => {
    it('computes path attributions and issues Ed25519 clearance tokens', () => {
      const attributor = new PathIntegratedGradientsAttributor(5);
      const x = new Float32Array(8).fill(0.2);
      const xPrime = new Float32Array(8).fill(0.0);
      const weights = new Float32Array(8).fill(0.1);

      const cert = attributor.issueClearanceToken('tx_clearance_1', x, xPrime, weights, 0.60);
      expect(cert.cleared).toBe(true);
      expect(cert.clearanceToken).toBeDefined();
      expect(cert.totalAttributionSum).toBeLessThanOrEqual(0.60);
    });

    it('adapts non-conformity threshold under ACI risk control', () => {
      const aci = new AdaptiveConformalInference(0.001, 0.01, 0.70);
      const res1 = aci.update(0.85); // Violation
      expect(res1.violation).toBe(true);
      expect(res1.currentThreshold).toBeLessThan(0.70); // Lowers threshold on violation
    });
  });

  describe('Tier2CausalEngine (Integrated Sidecar)', () => {
    it('clears benign low-risk actions and emits clearance token', () => {
      const sidecar = new Tier2CausalEngine();
      const features = new Float32Array(16).fill(0.05);

      const verdict = sidecar.evaluateCausalAction('tx_sidecar_01', 'agent', 'tool_fetch', 'call', features);
      expect(verdict.cleared).toBe(true);
      expect(verdict.clearanceToken).toBeDefined();
      expect(verdict.causalRiskScore).toBeLessThan(0.5);
    });

    it('rejects action and flags persistent cycle when exfiltration loop is formed', () => {
      const sidecar = new Tier2CausalEngine();
      const features = new Float32Array(16).fill(0.8);

      // Create cyclic data flow: toolA -> toolB -> toolC -> toolA
      sidecar.evaluateCausalAction('tx_c1', 'toolA', 'toolB', 'transfer', features);
      sidecar.evaluateCausalAction('tx_c2', 'toolB', 'toolC', 'transfer', features);
      sidecar.evaluateCausalAction('tx_c3', 'toolC', 'toolD', 'transfer', features);
      const verdict = sidecar.evaluateCausalAction('tx_c4', 'toolD', 'toolA', 'exfil', features, true);

      expect(verdict.topologicalCycleDetected).toBe(true);
      expect(verdict.cleared).toBe(false);
      expect(verdict.clearanceToken).toBeUndefined();
    });

    it('drains LMAX Disruptor ring buffer asynchronously', () => {
      const sidecar = new Tier2CausalEngine();
      const ring = new LmaxDisruptorRing();

      ring.enqueue('tx_ring_1', Buffer.from('payload-1'));
      ring.enqueue('tx_ring_2', Buffer.from('payload-2'));

      const drained = sidecar.drainRingBuffer(ring, 10);
      expect(drained).toBe(2);
      expect(ring.getOccupancy()).toBe(0);
    });
  });
});
