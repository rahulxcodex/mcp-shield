import * as crypto from 'crypto';

export type TransactionPhase = 'INITIATED' | 'PREPARED' | 'COMMITTED' | 'ABORTED';

export interface StagedAction {
  transactionId: string;
  actionType: string;
  payload: Record<string, unknown>;
  createdAt: number;
  cowBuffer?: Buffer;
  phase: TransactionPhase;
  clearanceToken?: string;
  rejectionReason?: string;
}

export interface TwoPhaseCommitResult {
  committed: boolean;
  transactionId: string;
  phase: TransactionPhase;
  reason?: string;
  durationMs: number;
}

/**
 * Capability Two-Phase Commit (2PC) & Speculative Sandboxing Engine
 * Manages atomic execution boundaries for high-impact mutations:
 * - Low-blast actions dispatch immediately
 * - High-impact mutations execute inside a Copy-On-Write staging arena during PREPARE
 * - Requires Ed25519 causal clearance token from Tier 2 sidecar within 30ms
 * - Enforces fail-closed ABORT on timeout or anomalous graph detection
 */
export class CapabilityTwoPhaseCommit {
  public static readonly DEFAULT_TIMEOUT_MS: number = 30; // 30ms SLA window

  private readonly stagedTransactions: Map<string, StagedAction> = new Map();
  private readonly tier2PublicKey: crypto.KeyObject;
  private readonly timeoutMs: number;

  constructor(tier2PublicKeyPem?: string, timeoutMs: number = CapabilityTwoPhaseCommit.DEFAULT_TIMEOUT_MS) {
    this.timeoutMs = timeoutMs;

    if (tier2PublicKeyPem) {
      this.tier2PublicKey = crypto.createPublicKey(tier2PublicKeyPem);
    } else {
      // Ephemeral Ed25519 keypair for local test & fallback isolation
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      this.tier2PublicKey = publicKey;
    }
  }

  /**
   * Phase 1: PREPARE
   * Stages high-impact mutation in Copy-On-Write memory buffer
   */
  public prepare(actionType: string, payload: Record<string, unknown>): StagedAction {
    const transactionId = `tx_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const cowBuffer = Buffer.from(JSON.stringify(payload), 'utf8');

    const staged: StagedAction = {
      transactionId,
      actionType,
      payload,
      createdAt: Date.now(),
      cowBuffer,
      phase: 'PREPARED'
    };

    this.stagedTransactions.set(transactionId, staged);
    return staged;
  }

  /**
   * Verifies an Ed25519 causal clearance token emitted by Tier 2
   */
  public verifyClearanceToken(transactionId: string, tokenHex: string): boolean {
    try {
      const msg = Buffer.from(`2PC_CLEARANCE:${transactionId}`, 'utf8');
      const sig = Buffer.from(tokenHex, 'hex');
      return crypto.verify(null, msg, this.tier2PublicKey, sig);
    } catch {
      return false;
    }
  }

  /**
   * Phase 2: COMMIT
   * Commits staged mutation if clearance token is valid and within 30ms window
   */
  public commit(transactionId: string, clearanceTokenHex: string): TwoPhaseCommitResult {
    const staged = this.stagedTransactions.get(transactionId);
    if (!staged) {
      return {
        committed: false,
        transactionId,
        phase: 'ABORTED',
        reason: `Transaction '${transactionId}' not found`,
        durationMs: 0
      };
    }

    const duration = Date.now() - staged.createdAt;

    // Timeout verification
    if (duration > this.timeoutMs) {
      this.abort(transactionId, `Commit timeout exceeded (${duration}ms > ${this.timeoutMs}ms)`);
      return {
        committed: false,
        transactionId,
        phase: 'ABORTED',
        reason: `Tier 2 2PC timeout exceeded (${duration}ms > ${this.timeoutMs}ms)`,
        durationMs: duration
      };
    }

    // Cryptographic clearance token verification
    const isValid = this.verifyClearanceToken(transactionId, clearanceTokenHex);
    if (!isValid) {
      this.abort(transactionId, 'Invalid Ed25519 clearance token signature');
      return {
        committed: false,
        transactionId,
        phase: 'ABORTED',
        reason: 'Invalid Ed25519 clearance token signature',
        durationMs: duration
      };
    }

    staged.phase = 'COMMITTED';
    staged.clearanceToken = clearanceTokenHex;
    // Release COW buffer to host
    this.stagedTransactions.delete(transactionId);

    return {
      committed: true,
      transactionId,
      phase: 'COMMITTED',
      durationMs: duration
    };
  }

  /**
   * Phase 2 (Abort): Fail-closed drop of COW staging arena
   */
  public abort(transactionId: string, reason: string): void {
    const staged = this.stagedTransactions.get(transactionId);
    if (staged) {
      staged.phase = 'ABORTED';
      staged.rejectionReason = reason;
      // Zero out COW buffer immediately to prevent memory leakage
      if (staged.cowBuffer) {
        staged.cowBuffer.fill(0);
      }
      this.stagedTransactions.delete(transactionId);
    }
  }

  public getPendingCount(): number {
    return this.stagedTransactions.size;
  }
}
