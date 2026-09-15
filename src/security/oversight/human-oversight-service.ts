import * as crypto from 'crypto';
import { SecurityDecision } from '../decision';

export type OversightStatus = 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface OversightApproval {
  reviewer: string;
  timestamp: string;
  comment?: string;
}

export interface PendingOversightRecord {
  id: string;
  requestId: string;
  action: 'QUARANTINE' | 'BLOCK';
  riskScore: number;
  detectorIds: string[];
  reasons: string[];
  status: OversightStatus;
  createdAt: number;
  expiresAt: number;
  approvals: OversightApproval[];
  requiredQuorum: number;
  context?: Record<string, unknown>;
}

export interface OversightVerdict {
  id: string;
  status: OversightStatus;
  allowed: boolean;
  quorumSatisfied: boolean;
  approvalsCount: number;
  requiredQuorum: number;
  message: string;
}

/**
 * Human Oversight Service (EU AI Act Article 14 Human Oversight Compliance)
 * Provides mandatory human-in-the-loop validation and four-eyes quorum approval
 * for all high-risk QUARANTINE and BLOCK decisions originating from automated ML fusion.
 */
export class HumanOversightService {
  public static readonly DEFAULT_TTL_MS: number = 300000; // 5 minutes
  private readonly pendingRecords: Map<string, PendingOversightRecord> = new Map();
  private readonly defaultQuorum: number;
  private readonly ttlMs: number;

  constructor(options?: { defaultQuorum?: number; ttlMs?: number }) {
    this.defaultQuorum = options?.defaultQuorum ?? 1;
    this.ttlMs = options?.ttlMs ?? HumanOversightService.DEFAULT_TTL_MS;
  }

  /**
   * Enqueues an automated security decision for mandatory human oversight
   */
  public submitForReview(
    decision: { requestId: string; action: string; riskScore: number; detectorIds?: string[]; reasons?: string[]; [key: string]: unknown },
    context?: Record<string, unknown>,
    customQuorum?: number
  ): PendingOversightRecord {
    const id = `ovs_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    const now = Date.now();

    const record: PendingOversightRecord = {
      id,
      requestId: decision.requestId,
      action: (decision.action === 'QUARANTINE' ? 'QUARANTINE' : 'BLOCK'),
      riskScore: decision.riskScore,
      detectorIds: decision.detectorIds || [],
      reasons: decision.reasons || [],
      status: 'PENDING_REVIEW',
      createdAt: now,
      expiresAt: now + this.ttlMs,
      approvals: [],
      requiredQuorum: customQuorum ?? this.defaultQuorum,
      context
    };

    this.pendingRecords.set(id, record);
    return record;
  }

  /**
   * Records human reviewer approval (supporting 4-eyes multi-reviewer quorum)
   */
  public approve(recordId: string, reviewer: string, comment?: string): OversightVerdict {
    const record = this.pendingRecords.get(recordId);
    if (!record) {
      return {
        id: recordId,
        status: 'REJECTED',
        allowed: false,
        quorumSatisfied: false,
        approvalsCount: 0,
        requiredQuorum: this.defaultQuorum,
        message: `Oversight record '${recordId}' not found`
      };
    }

    if (Date.now() > record.expiresAt) {
      record.status = 'EXPIRED';
      return {
        id: recordId,
        status: 'EXPIRED',
        allowed: false,
        quorumSatisfied: false,
        approvalsCount: record.approvals.length,
        requiredQuorum: record.requiredQuorum,
        message: 'Oversight review request has expired'
      };
    }

    // Check if reviewer has already approved (prevent self-duplication)
    const existing = record.approvals.find((a) => a.reviewer === reviewer);
    if (!existing) {
      record.approvals.push({
        reviewer,
        timestamp: new Date().toISOString(),
        comment
      });
    }

    const quorumSatisfied = record.approvals.length >= record.requiredQuorum;
    if (quorumSatisfied) {
      record.status = 'APPROVED';
    }

    return {
      id: recordId,
      status: record.status,
      allowed: quorumSatisfied,
      quorumSatisfied,
      approvalsCount: record.approvals.length,
      requiredQuorum: record.requiredQuorum,
      message: quorumSatisfied
        ? `Decision approved with ${record.approvals.length}/${record.requiredQuorum} approvals`
        : `Approval recorded. Need ${record.requiredQuorum - record.approvals.length} more approval(s)`
    };
  }

  /**
   * Explicit human rejection upholding the BLOCK / QUARANTINE decision
   */
  public reject(recordId: string, reviewer: string, reason?: string): OversightVerdict {
    const record = this.pendingRecords.get(recordId);
    if (!record) {
      return {
        id: recordId,
        status: 'REJECTED',
        allowed: false,
        quorumSatisfied: false,
        approvalsCount: 0,
        requiredQuorum: this.defaultQuorum,
        message: `Oversight record '${recordId}' not found`
      };
    }

    record.status = 'REJECTED';
    return {
      id: recordId,
      status: 'REJECTED',
      allowed: false,
      quorumSatisfied: false,
      approvalsCount: record.approvals.length,
      requiredQuorum: record.requiredQuorum,
      message: `Action confirmed blocked by reviewer ${reviewer}: ${reason || 'Decision upheld'}`
    };
  }

  public listPending(statusFilter?: OversightStatus): PendingOversightRecord[] {
    const now = Date.now();
    const results: PendingOversightRecord[] = [];

    for (const record of this.pendingRecords.values()) {
      if (record.status === 'PENDING_REVIEW' && now > record.expiresAt) {
        record.status = 'EXPIRED';
      }
      if (!statusFilter || record.status === statusFilter) {
        results.push(record);
      }
    }

    return results;
  }

  public getRecord(recordId: string): PendingOversightRecord | undefined {
    return this.pendingRecords.get(recordId);
  }

  public clear(): void {
    this.pendingRecords.clear();
  }
}
