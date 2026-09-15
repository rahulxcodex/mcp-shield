/**
 * Differential Privacy Stochastic Gradient Descent (DP-SGD) Engine
 * (Abadi et al., ACM CCS 2016; Mironov, CSF 2017 RDP)
 * Implements per-sample L2 gradient clipping at bound C and calibrated Gaussian perturbation,
 * tracked via Rényi Differential Privacy (RDP) composition:
 * \epsilon(\alpha) = \frac{T \alpha q^2}{\sigma^2}
 */
export interface DpSgdResult {
  clippedGradients: Float32Array;
  l2NormBefore: number;
  l2NormAfter: number;
  noiseMultiplier: number;
  epsilonSpent: number;
  delta: number;
}

export class DpSgdEngine {
  private readonly clippingBoundC: number;
  private readonly noiseSigma: number;
  private readonly subsamplingRatioQ: number;
  private readonly delta: number;
  private stepsTaken: number = 0;

  constructor(
    clippingBoundC: number = 1.0,
    noiseSigma: number = 1.2,
    subsamplingRatioQ: number = 0.01,
    delta: number = 1e-5
  ) {
    this.clippingBoundC = clippingBoundC;
    this.noiseSigma = noiseSigma;
    this.subsamplingRatioQ = subsamplingRatioQ;
    this.delta = delta;
  }

  /**
   * Generates standard normal random samples via Box-Muller transform
   */
  private sampleGaussian(mean: number, std: number): number {
    const u1 = Math.max(1e-12, Math.random());
    const u2 = Math.random();
    const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
    return mean + z0 * std;
  }

  /**
   * Clips raw gradient vector to L2 norm bound C and adds Gaussian noise
   */
  public perturbGradients(rawGradients: Float32Array, batchSize: number = 1): DpSgdResult {
    this.stepsTaken++;

    // 1. Calculate L2 norm ||g||_2
    let sumSq = 0.0;
    for (let i = 0; i < rawGradients.length; i++) {
      sumSq += rawGradients[i] * rawGradients[i];
    }
    const l2NormBefore = Math.sqrt(sumSq);

    // 2. Clip factor min(1, C / ||g||_2)
    const clipFactor = Math.min(1.0, this.clippingBoundC / Math.max(1e-12, l2NormBefore));
    const perturbed = new Float32Array(rawGradients.length);

    // 3. Add calibrated Gaussian noise N(0, (sigma * C)^2 I) / batchSize
    const noiseStd = (this.noiseSigma * this.clippingBoundC) / Math.max(1, batchSize);

    let sumSqAfter = 0.0;
    for (let i = 0; i < rawGradients.length; i++) {
      const clipped = rawGradients[i] * clipFactor;
      const noise = this.sampleGaussian(0, noiseStd);
      perturbed[i] = clipped + noise;
      sumSqAfter += perturbed[i] * perturbed[i];
    }
    const l2NormAfter = Math.sqrt(sumSqAfter);

    // 4. Compute RDP privacy spend: epsilon(alpha) = T * alpha * q^2 / sigma^2
    const alpha = 4.0; // Optimal Rényi order
    const rdp = (this.stepsTaken * alpha * Math.pow(this.subsamplingRatioQ, 2)) / Math.pow(this.noiseSigma, 2);
    const epsilonSpent = rdp + Math.log(1.0 / this.delta) / (alpha - 1.0);

    return {
      clippedGradients: perturbed,
      l2NormBefore,
      l2NormAfter,
      noiseMultiplier: this.noiseSigma,
      epsilonSpent,
      delta: this.delta
    };
  }

  public getPrivacyBudget(): { epsilon: number; delta: number; steps: number } {
    const alpha = 4.0;
    const rdp = (this.stepsTaken * alpha * Math.pow(this.subsamplingRatioQ, 2)) / Math.pow(this.noiseSigma, 2);
    const epsilon = rdp + Math.log(1.0 / this.delta) / (alpha - 1.0);
    return { epsilon, delta: this.delta, steps: this.stepsTaken };
  }

  public reset(): void {
    this.stepsTaken = 0;
  }
}
