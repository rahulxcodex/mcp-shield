import {
  DpSgdEngine,
  ByzantineSecAggCoordinator,
  ClientUpdate
} from '../../src';

describe('Privacy-Preserving Federated Intelligence Suite (Blueprint Section 4)', () => {
  describe('DpSgdEngine (Rényi Differential Privacy)', () => {
    it('enforces L2 clipping bound C and perturbs gradients', () => {
      const dp = new DpSgdEngine(1.0, 1.2, 0.01, 1e-5);
      // Create high-norm gradient vector
      const rawGrad = new Float32Array([3.0, 4.0]); // Norm = 5.0 > C = 1.0

      const result = dp.perturbGradients(rawGrad, 1);
      expect(result.l2NormBefore).toBe(5.0);
      expect(result.epsilonSpent).toBeGreaterThan(0.0);
      expect(result.clippedGradients.length).toBe(2);
    });

    it('tracks cumulative privacy spend across training iterations', () => {
      const dp = new DpSgdEngine(1.0, 1.2, 0.01, 1e-5);
      const grad = new Float32Array([0.1, 0.2]);

      const res1 = dp.perturbGradients(grad, 1);
      const res2 = dp.perturbGradients(grad, 1);

      expect(res2.epsilonSpent).toBeGreaterThan(res1.epsilonSpent);
      const budget = dp.getPrivacyBudget();
      expect(budget.steps).toBe(2);
    });
  });

  describe('ByzantineSecAggCoordinator (Bulletproofs & FLAME)', () => {
    it('generates and verifies 672-byte Bulletproofs norm range proofs', () => {
      const coordinator = new ByzantineSecAggCoordinator(1.0);
      const deltaW = new Float32Array([0.2, -0.3, 0.1]);

      const proof = ByzantineSecAggCoordinator.generateRangeProof(deltaW, 1.0);
      expect(proof.length).toBe(672);

      const isValid = coordinator.verifyRangeProof(proof);
      expect(isValid).toBe(true);
    });

    it('rejects updates exceeding the certified L2 norm bound', () => {
      const coordinator = new ByzantineSecAggCoordinator(1.0);
      const deltaW = new Float32Array([2.0, 2.0]); // Norm ~ 2.8 > bound 1.0

      const proof = ByzantineSecAggCoordinator.generateRangeProof(deltaW, 1.0);
      const isValid = coordinator.verifyRangeProof(proof);
      expect(isValid).toBe(false);
    });

    it('cancels pairwise blinding masks during aggregation', () => {
      const coordinator = new ByzantineSecAggCoordinator(10.0);
      const dim = 4;

      // Client 1 with update [1, 2, 3, 4]
      const delta1 = new Float32Array([1.0, 2.0, 3.0, 4.0]);
      // Client 2 with update [2, 3, 4, 5]
      const delta2 = new Float32Array([2.0, 3.0, 4.0, 5.0]);

      const mask = ByzantineSecAggCoordinator.computePairwiseMask(1, 2, dim);

      // Client 1 adds mask: y_1 = delta_1 + mask
      const blinded1 = new Float32Array(dim);
      for (let i = 0; i < dim; i++) blinded1[i] = delta1[i] + mask[i];

      // Client 2 subtracts mask: y_2 = delta_2 - mask
      const blinded2 = new Float32Array(dim);
      for (let i = 0; i < dim; i++) blinded2[i] = delta2[i] - mask[i];

      const proof1 = ByzantineSecAggCoordinator.generateRangeProof(delta1, 6.0);
      const proof2 = ByzantineSecAggCoordinator.generateRangeProof(delta2, 8.0);

      const updates: ClientUpdate[] = [
        { clientId: 1, blindedWeights: blinded1, proofPayload: proof1, l2NormReported: 5.4 },
        { clientId: 2, blindedWeights: blinded2, proofPayload: proof2, l2NormReported: 7.3 }
      ];

      const res = coordinator.aggregate(updates);
      expect(res.participatingClients).toEqual([1, 2]);
      expect(res.rejectedClients.length).toBe(0);

      // Expect average: (1 + 2)/2 = 1.5, (2 + 3)/2 = 2.5, etc.
      expect(res.aggregatedWeights[0]).toBeCloseTo(1.5, 1);
      expect(res.aggregatedWeights[1]).toBeCloseTo(2.5, 1);
    });
  });
});
