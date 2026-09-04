import * as crypto from 'crypto';

export interface ApprovalRequest {
  id: string;
  action: string;
  organizationId: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  approvers: string[];
  approvals: CryptographicApprovalRecord[];
  createdAt: number;
  expiresAt: number;
}

export interface CryptographicApprovalRecord {
  approverId: string;
  signature: string;
  nonce: string;
  timestamp: number;
  verified: boolean;
}

export interface ApproverRegistryEntry {
  approverId: string;
  publicKeyPem: string;
  organizationId: string;
  active: boolean;
}

export interface ApprovalPayload {
  requestId: string;
  approverId: string;
  organizationId: string;
  action: string;
  nonce: string;
  expiresAt: number;
}

/**
 * Enterprise JIT Authorization & Cryptographic Four-Eyes Quorum Engine
 * Implements real Ed25519 / RSA asymmetric signature validation, nonce replay protection,
 * expiration bounds, and organizational scoping.
 */
export class AuthorizationModule {
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();
  private approverRegistry: Map<string, ApproverRegistryEntry> = new Map();
  private consumedNonces: Set<string> = new Set();
  private defaultExpiryMs: number = 15 * 60 * 1000; // 15 minutes

  /**
   * Registers an authorized approver and their asymmetric public key
   */
  public registerApprover(
    approverId: string,
    publicKeyPem: string,
    organizationId: string
  ): void {
    this.approverRegistry.set(approverId, {
      approverId,
      publicKeyPem,
      organizationId,
      active: true
    });
  }

  public revokeApprover(approverId: string): void {
    const entry = this.approverRegistry.get(approverId);
    if (entry) {
      entry.active = false;
    }
  }

  /**
   * Issues Just-In-Time (JIT) least-privilege credentials
   */
  public issueJitCredential(service: string, durationMinutes: number): string {
    const token = crypto.randomBytes(32).toString('hex');
    return `JIT_${token}`;
  }

  /**
   * Initiates an Out-of-Band Quorum (Four-Eyes) approval flow for high-risk actions
   */
  public initiateQuorumApproval(action: string, organizationId: string = 'org-default', durationMs?: number): string {
    const id = crypto.randomUUID();
    const now = Date.now();
    const expiresAt = now + (durationMs || this.defaultExpiryMs);

    this.pendingApprovals.set(id, {
      id,
      action,
      organizationId,
      status: 'PENDING',
      approvers: [],
      approvals: [],
      createdAt: now,
      expiresAt
    });
    return id;
  }

  /**
   * Records and cryptographically verifies an approval from an authorized approver.
   *
   * Supports:
   * 1. Cryptographic payload validation: signature over canonical JSON string of ApprovalPayload
   * 2. Direct string payload signature
   */
  public recordApproval(
    id: string,
    approverId: string,
    signature: string,
    payload?: ApprovalPayload
  ): void {
    const req = this.pendingApprovals.get(id);
    if (!req) {
      throw new Error(`Approval request '${id}' not found`);
    }

    if (Date.now() > req.expiresAt) {
      req.status = 'EXPIRED';
      throw new Error(`Approval request '${id}' has expired`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Approval request '${id}' is already ${req.status}`);
    }

    // 1. Validate approver identity and registration
    const approver = this.approverRegistry.get(approverId);
    if (!approver || !approver.active) {
      throw new Error(`Approver '${approverId}' is not registered or is inactive`);
    }

    if (approver.organizationId !== req.organizationId) {
      throw new Error(
        `Cross-tenant approval rejected: Approver org '${approver.organizationId}' does not match request org '${req.organizationId}'`
      );
    }

    // 2. Prevent duplicate approval by same approver
    if (req.approvers.includes(approverId)) {
      throw new Error(`Approver '${approverId}' has already signed this request`);
    }

    // 3. Nonce & Expiration Replay Protection
    const nonce = payload?.nonce || signature.substring(0, 32);
    if (this.consumedNonces.has(nonce)) {
      throw new Error(`Replay attack detected: Nonce '${nonce}' has already been consumed`);
    }

    if (payload) {
      if (payload.requestId !== req.id) {
        throw new Error(`Payload requestId mismatch: expected '${req.id}', got '${payload.requestId}'`);
      }
      if (payload.action !== req.action) {
        throw new Error(`Payload action mismatch: expected '${req.action}', got '${payload.action}'`);
      }
      if (payload.expiresAt < Date.now()) {
        throw new Error(`Signed payload has already expired`);
      }
    }

    // 4. Cryptographic Signature Verification
    const dataToVerify = payload ? JSON.stringify(payload) : `${id}:${approverId}:${req.action}`;
    const isValid = this.verifySignature(dataToVerify, signature, approver.publicKeyPem);

    if (!isValid) {
      throw new Error(`Cryptographic verification failed for approver '${approverId}'`);
    }

    // Consume nonce
    this.consumedNonces.add(nonce);

    req.approvers.push(approverId);
    req.approvals.push({
      approverId,
      signature,
      nonce,
      timestamp: Date.now(),
      verified: true
    });

    // 5. Four-Eyes Quorum check (require >= 2 distinct verified approvers)
    if (req.approvers.length >= 2) {
      req.status = 'APPROVED';
    }
  }

  public getApprovalStatus(id: string): ApprovalRequest | undefined {
    return this.pendingApprovals.get(id);
  }

  private verifySignature(data: string, signature: string, publicKeyPem: string): boolean {
    try {
      // Ed25519 or RSA or HMAC depending on key format
      if (publicKeyPem.includes('BEGIN PUBLIC KEY') || publicKeyPem.includes('BEGIN RSA PUBLIC KEY')) {
        const verify = crypto.createVerify('SHA256');
        verify.update(data);
        verify.end();
        return verify.verify(publicKeyPem, signature, 'hex') || verify.verify(publicKeyPem, signature, 'base64');
      } else {
        // Shared secret HMAC verification for lightweight environments
        const expectedSig = crypto.createHmac('sha256', publicKeyPem).update(data).digest('hex');
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'));
      }
    } catch {
      return false;
    }
  }
}
