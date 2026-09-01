import * as crypto from 'crypto';

export interface ElevationLease {
  leaseId: string;
  toolName: string;
  grantedBy: string;
  reason: string;
  grantedAt: number;
  expiresAt: number;
  remainingExecutions: number;
}

export class JITElevationManager {
  private leases: Map<string, ElevationLease> = new Map();

  public grantLease(
    toolName: string,
    grantedBy: string,
    reason: string,
    durationSeconds: number = 300,
    maxExecutions: number = 5
  ): ElevationLease {
    const leaseId = `lease_${crypto.randomBytes(8).toString('hex')}`;
    const now = Date.now();
    const lease: ElevationLease = {
      leaseId,
      toolName: toolName.trim().toLowerCase(),
      grantedBy,
      reason,
      grantedAt: now,
      expiresAt: now + durationSeconds * 1000,
      remainingExecutions: maxExecutions
    };

    this.leases.set(toolName.trim().toLowerCase(), lease);
    return lease;
  }

  public checkAndConsumeElevation(toolName: string): { elevated: boolean; lease?: ElevationLease; reason?: string } {
    const normalized = (toolName || '').trim().toLowerCase();
    const lease = this.leases.get(normalized);

    if (!lease) {
      return { elevated: false, reason: 'NO_ACTIVE_LEASE' };
    }

    const now = Date.now();
    if (now > lease.expiresAt) {
      this.leases.delete(normalized);
      return { elevated: false, reason: 'LEASE_EXPIRED' };
    }

    if (lease.remainingExecutions <= 0) {
      this.leases.delete(normalized);
      return { elevated: false, reason: 'LEASE_QUOTA_EXHAUSTED' };
    }

    lease.remainingExecutions -= 1;
    if (lease.remainingExecutions <= 0) {
      this.leases.delete(normalized);
    }

    return { elevated: true, lease };
  }

  public revokeLease(toolName: string): boolean {
    const normalized = (toolName || '').trim().toLowerCase();
    return this.leases.delete(normalized);
  }

  public listActiveLeases(): ElevationLease[] {
    const now = Date.now();
    const active: ElevationLease[] = [];
    for (const [tool, lease] of this.leases.entries()) {
      if (now <= lease.expiresAt && lease.remainingExecutions > 0) {
        active.push(lease);
      } else {
        this.leases.delete(tool);
      }
    }
    return active;
  }
}
