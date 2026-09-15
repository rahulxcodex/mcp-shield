import * as crypto from 'crypto';

/**
 * Path-Integrated Gradients Attribution Engine
 * (Sundararajan et al., ICML 2017 "Axiomatic Attribution for Deep Networks")
 * Evaluates path attribution:
 * A(e) = (x_e - x_e') \odot \int_0^1 \nabla_{x_e} F(x_e' + \alpha(x_e - x_e')) d\alpha
 * Emits Ed25519-signed causal clearance token \sigma_{auth} upon attribution verification.
 */
export interface AttributionCertificate {
  transactionId: string;
  cleared: boolean;
  clearanceToken?: string; // Ed25519 signature hex
  attributions: Float32Array;
  topAttributedFeatures: string[];
  totalAttributionSum: number;
}

export class PathIntegratedGradientsAttributor {
  private readonly signingKey: crypto.KeyObject;
  public readonly publicKey: crypto.KeyObject;
  private readonly numSteps: number;

  constructor(numSteps: number = 10, keyPair?: { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject }) {
    this.numSteps = numSteps;
    if (keyPair) {
      this.signingKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.signingKey = generated.privateKey;
      this.publicKey = generated.publicKey;
    }
  }

  /**
   * Dummy surrogate evaluation function F(x) = sum(w_i * x_i)
   */
  private gradientSurrogate(x: Float32Array, weights: Float32Array): Float32Array {
    const grad = new Float32Array(x.length);
    for (let i = 0; i < x.length; i++) {
      grad[i] = weights[i % weights.length];
    }
    return grad;
  }

  /**
   * Computes integrated gradients between baseline x_prime and input x
   */
  public computeAttributions(
    x: Float32Array,
    xPrime: Float32Array,
    modelWeights: Float32Array,
    featureNames?: string[]
  ): { attributions: Float32Array; topFeatures: string[]; totalSum: number } {
    const dim = x.length;
    const accumulatedGrad = new Float32Array(dim);
    const stepSize = 1.0 / this.numSteps;

    // Riemann sum approximation of the path integral
    for (let step = 0; step < this.numSteps; step++) {
      const alpha = (step + 0.5) * stepSize;
      const interp = new Float32Array(dim);
      for (let i = 0; i < dim; i++) {
        interp[i] = xPrime[i] + alpha * (x[i] - xPrime[i]);
      }
      const grad = this.gradientSurrogate(interp, modelWeights);
      for (let i = 0; i < dim; i++) {
        accumulatedGrad[i] += grad[i] * stepSize;
      }
    }

    // A_i = (x_i - x'_i) * accumulatedGrad_i
    const attributions = new Float32Array(dim);
    let totalSum = 0.0;
    for (let i = 0; i < dim; i++) {
      attributions[i] = (x[i] - xPrime[i]) * accumulatedGrad[i];
      totalSum += attributions[i];
    }

    // Rank top features
    const indexed = Array.from(attributions).map((val, idx) => ({
      idx,
      val: Math.abs(val),
      name: featureNames?.[idx] || `feature_${idx}`
    }));
    indexed.sort((a, b) => b.val - a.val);
    const topFeatures = indexed.slice(0, 3).map((f) => `${f.name}:${f.val.toFixed(3)}`);

    return { attributions, topFeatures, totalSum };
  }

  /**
   * Certifies causal intent and signs Ed25519 clearance token
   */
  public issueClearanceToken(
    transactionId: string,
    x: Float32Array,
    xPrime: Float32Array,
    modelWeights: Float32Array,
    riskThreshold: number = 0.50
  ): AttributionCertificate {
    const { attributions, topFeatures, totalSum } = this.computeAttributions(x, xPrime, modelWeights);

    // If total attribution does not exceed risk threshold, action is certified benign
    const cleared = totalSum <= riskThreshold;
    let clearanceToken: string | undefined;

    if (cleared) {
      const msg = Buffer.from(`2PC_CLEARANCE:${transactionId}`, 'utf8');
      const sig = crypto.sign(null, msg, this.signingKey);
      clearanceToken = sig.toString('hex');
    }

    return {
      transactionId,
      cleared,
      clearanceToken,
      attributions,
      topAttributedFeatures: topFeatures,
      totalAttributionSum: totalSum
    };
  }

  public getPublicKeyPem(): string {
    return this.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }
}
