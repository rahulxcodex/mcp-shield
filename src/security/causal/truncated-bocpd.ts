/**
 * Truncated Bayesian Online Changepoint Detection (BOCPD)
 * (Adams & MacKay, 2007)
 * Implements recursive message passing with hazard function truncated at r_max = 128:
 * H(r) = 1/lambda for r < r_max, and 1.0 for r >= r_max.
 * Statically pre-allocates Float64Array[128] slabs for zero runtime heap allocations.
 */
export interface BocpdResult {
  changepointDetected: boolean;
  maxRunLength: number;
  changepointProbability: number;
  posteriorEntropy: number;
}

export class TruncatedBocpdEngine {
  public static readonly R_MAX: number = 128;

  private readonly hazardLambda: number;
  // Pre-allocated run-length posterior slab: P(r_t | x_{1:t})
  private readonly runLengthPosterior: Float64Array;
  private readonly tempPosterior: Float64Array;

  // Running Gaussian sufficient statistics
  private mean: number = 0.0;
  private var: number = 1.0;
  private count: number = 0;

  constructor(hazardLambda: number = 50.0) {
    this.hazardLambda = hazardLambda;
    this.runLengthPosterior = new Float64Array(TruncatedBocpdEngine.R_MAX);
    this.tempPosterior = new Float64Array(TruncatedBocpdEngine.R_MAX);

    // Initial prior: P(r_0 = 0) = 1.0
    this.runLengthPosterior[0] = 1.0;
  }

  /**
   * Evaluates hazard function H(r)
   */
  private hazard(r: number): number {
    if (r >= TruncatedBocpdEngine.R_MAX - 1) return 1.0;
    return 1.0 / this.hazardLambda;
  }

  /**
   * Evaluates predictive probability under running Gaussian model
   */
  private predictiveProb(x: number): number {
    const sigma = Math.sqrt(Math.max(0.01, this.var));
    const diff = x - this.mean;
    const exponent = -0.5 * (diff * diff) / (sigma * sigma);
    return (1.0 / (sigma * Math.sqrt(2 * Math.PI))) * Math.exp(exponent);
  }

  /**
   * Processes a new observation x_t and updates the run-length posterior
   */
  public step(observation: number): BocpdResult {
    const pred = Math.max(1e-8, this.predictiveProb(observation));
    this.tempPosterior.fill(0);

    let changepointEvidence = 0.0;
    const rMax = TruncatedBocpdEngine.R_MAX;
    const priorPred = 0.05; // Base prior predictive density for changepoint regime

    // 1. Calculate growth probabilities P(r_t = r_{t-1} + 1)
    for (let r = 0; r < rMax - 1; r++) {
      const prevProb = this.runLengthPosterior[r];
      if (prevProb <= 0) continue;

      const h = this.hazard(r);
      // Growth probability
      this.tempPosterior[r + 1] = prevProb * pred * (1.0 - h);
      // Accumulate changepoint mass P(r_t = 0)
      changepointEvidence += prevProb * priorPred * h;
    }

    // Assign changepoint probability
    this.tempPosterior[0] = changepointEvidence;

    // 2. Normalize posterior
    let sum = 0.0;
    for (let r = 0; r < rMax; r++) {
      sum += this.tempPosterior[r];
    }
    if (sum > 0) {
      const invSum = 1.0 / sum;
      for (let r = 0; r < rMax; r++) {
        this.runLengthPosterior[r] = this.tempPosterior[r] * invSum;
      }
    } else {
      this.runLengthPosterior[0] = 1.0;
    }

    // 3. Update running statistics
    this.count++;
    const delta = observation - this.mean;
    this.mean += delta / this.count;
    const delta2 = observation - this.mean;
    this.var += (delta * delta2 - this.var) / this.count;

    // 4. Extract posterior metrics
    let maxR = 0;
    let maxP = 0.0;
    let entropy = 0.0;

    for (let r = 0; r < rMax; r++) {
      const p = this.runLengthPosterior[r];
      if (p > maxP) {
        maxP = p;
        maxR = r;
      }
      if (p > 1e-12) {
        entropy -= p * Math.log2(p);
      }
    }

    const changepointProb = this.runLengthPosterior[0];
    const changepointDetected = changepointProb > 0.40;

    return {
      changepointDetected,
      maxRunLength: maxR,
      changepointProbability: changepointProb,
      posteriorEntropy: entropy
    };
  }

  public reset(): void {
    this.runLengthPosterior.fill(0);
    this.runLengthPosterior[0] = 1.0;
    this.mean = 0.0;
    this.var = 1.0;
    this.count = 0;
  }

  public getPosterior(): Float64Array {
    return this.runLengthPosterior;
  }
}
