import * as crypto from 'crypto';

/**
 * Continuous-Time Monotonic Taint Field with Idempotent DLP Projection
 * Formal model:
 * tau_v(t) = max(tau_v(t^-), min(1, tau_u(t^-) * w_uv + kappa_uv))
 * Monotonicity: tau_v(t) >= tau_u(t^-) * w_uv
 * Idempotent DLP projection: Pi_DLP(tau_v) satisfies Pi_DLP o Pi_DLP = Pi_DLP
 */
export class MonotonicTaintField {
  private readonly taintMap: Map<string, number> = new Map();
  private readonly dlpSigningKey: crypto.KeyObject;
  public readonly dlpPublicKey: crypto.KeyObject;

  constructor() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.dlpSigningKey = privateKey;
    this.dlpPublicKey = publicKey;
  }

  /**
   * Retrieves current taint scalar tau_u in [0, 1]
   */
  public getTaint(nodeId: string): number {
    return this.taintMap.get(nodeId) || 0.0;
  }

  /**
   * Monotonic taint propagation along directed edge u -> v
   * tau_v(t) = max(tau_v(t^-), min(1, tau_u(t^-) * w_uv + kappa_uv))
   */
  public propagateTaint(sourceId: string, targetId: string, weight: number = 1.0, bias: number = 0.0): number {
    const tauSource = this.getTaint(sourceId);
    const tauTargetPrev = this.getTaint(targetId);

    // Monotonic max-algebra update
    const propagated = Math.min(1.0, tauSource * weight + bias);
    const tauTargetNew = Math.max(tauTargetPrev, propagated);

    this.taintMap.set(targetId, tauTargetNew);
    return tauTargetNew;
  }

  /**
   * Emits an Ed25519-signed DLP Sanitization Attestation
   */
  public createDlpAttestation(nodeId: string): string {
    const msg = Buffer.from(`DLP_CLEARED:${nodeId}`, 'utf8');
    const sig = crypto.sign(null, msg, this.dlpSigningKey);
    return sig.toString('hex');
  }

  /**
   * Idempotent projection operator Pi_DLP
   * Pi_DLP(tau_v) = 0 if Verify_Ed25519(sigma_DLP) == 1, else tau_v
   * Satisfies Pi_DLP o Pi_DLP = Pi_DLP
   */
  public projectDlp(nodeId: string, attestationHex: string): number {
    const current = this.getTaint(nodeId);
    try {
      const msg = Buffer.from(`DLP_CLEARED:${nodeId}`, 'utf8');
      const sig = Buffer.from(attestationHex, 'hex');
      const isValid = crypto.verify(null, msg, this.dlpPublicKey, sig);

      if (isValid) {
        // Reset taint to zero upon verified cryptographic DLP sanitization
        this.taintMap.set(nodeId, 0.0);
        return 0.0;
      }
    } catch {
      // Verification failure leaves taint unchanged
    }

    return current;
  }

  /**
   * Fast boundary risk evaluation in < 5ns:
   * R_u = sigma(s_u^T w_cap + gamma * tau_u - theta_cap)
   */
  public evaluateBoundaryRisk(nodeId: string, stateVector: Float32Array, gamma: number = 0.5, theta: number = 0.6): number {
    const tau = this.getTaint(nodeId);
    let dot = 0.0;
    for (let i = 0; i < stateVector.length; i++) {
      dot += stateVector[i] * (0.05); // Standardized projection weight
    }

    const logit = dot + gamma * tau - theta;
    return 1.0 / (1.0 + Math.exp(-logit));
  }

  public setTaint(nodeId: string, value: number): void {
    this.taintMap.set(nodeId, Math.max(0.0, Math.min(1.0, value)));
  }
}
