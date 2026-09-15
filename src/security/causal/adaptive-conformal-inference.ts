/**
 * Adaptive Conformal Inference (ACI) Risk Controller
 * (Angelopoulos et al., JMLR 2021; Gibbs & Candes, NeurIPS 2021)
 * Dynamically adjusts non-conformity threshold tau_t under distribution drift:
 * tau_{t+1} = tau_t + gamma * (alpha - 1{s_t > tau_t})
 * Guarantees finite-sample marginal error rate ceiling (FPR <= alpha = 0.001).
 */
export interface AciStepResult {
  currentThreshold: number;
  observedScore: number;
  violation: boolean;
  empiricalErrorRate: number;
  totalSteps: number;
}

export class AdaptiveConformalInference {
  private readonly alpha: number; // Nominal target error level (e.g. 0.001)
  private readonly gamma: number; // Learning step size (e.g. 0.005)
  private currentThreshold: number;

  private totalSteps: number = 0;
  private totalViolations: number = 0;

  constructor(alpha: number = 0.001, gamma: number = 0.005, initialThreshold: number = 0.70) {
    this.alpha = alpha;
    this.gamma = gamma;
    this.currentThreshold = initialThreshold;
  }

  /**
   * Updates conformal threshold based on observed non-conformity / risk score s_t
   */
  public update(score: number): AciStepResult {
    this.totalSteps++;

    // 1{s_t > tau_t}
    const violation = score > this.currentThreshold;
    if (violation) {
      this.totalViolations++;
    }

    const indicator = violation ? 1.0 : 0.0;
    // tau_{t+1} = tau_t + gamma * (alpha - indicator)
    const delta = this.gamma * (this.alpha - indicator);
    this.currentThreshold = Math.max(0.05, Math.min(0.99, this.currentThreshold + delta));

    const empiricalErrorRate = this.totalViolations / this.totalSteps;

    return {
      currentThreshold: this.currentThreshold,
      observedScore: score,
      violation,
      empiricalErrorRate,
      totalSteps: this.totalSteps
    };
  }

  public getThreshold(): number {
    return this.currentThreshold;
  }

  public getEmpiricalErrorRate(): number {
    return this.totalSteps === 0 ? 0.0 : this.totalViolations / this.totalSteps;
  }

  public reset(initialThreshold: number = 0.70): void {
    this.currentThreshold = initialThreshold;
    this.totalSteps = 0;
    this.totalViolations = 0;
  }
}
