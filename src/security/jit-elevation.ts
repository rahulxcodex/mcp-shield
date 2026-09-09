import * as crypto from 'crypto';
import { hashCanonicalJson } from './canonical-json';

export interface ElevationLease {
  leaseId: string;
  toolName: string;
  requestFingerprint?: string;
  serverIdentity?: string;
  ruleId?: string;
  scope: 'request' | 'tool';
  grantedBy: string;
  reason: string;
  grantedAt: number;
  expiresAt: number;
  remainingExecutions: number;
}

export class JITElevationManager {
  private leases: Map<string, ElevationLease> = new Map();

  public static computeRequestFingerprint(
    serverIdentity: string,
    toolName: string,
    args: any,
    ruleId?: string
  ): string {
    const payload = {
      serverIdentity: (serverIdentity || '').trim(),
      toolName: (toolName || '').trim().toLowerCase(),
      args: args ?? {},
      ruleId: ruleId || ''
    };
    return hashCanonicalJson(payload);
  }

  public grantLease(
    toolName: string,
    grantedBy: string,
    reason: string,
    durationSeconds: number = 300,
    maxExecutions: number = 5,
    options?: {
      requestFingerprint?: string;
      serverIdentity?: string;
      ruleId?: string;
      scope?: 'request' | 'tool';
    }
  ): ElevationLease {
    const leaseId = `lease_${crypto.randomBytes(8).toString('hex')}`;
    const now = Date.now();
    const scope = options?.scope || (options?.requestFingerprint ? 'request' : 'tool');
    const lease: ElevationLease = {
      leaseId,
      toolName: toolName.trim().toLowerCase(),
      requestFingerprint: options?.requestFingerprint,
      serverIdentity: options?.serverIdentity,
      ruleId: options?.ruleId,
      scope,
      grantedBy,
      reason,
      grantedAt: now,
      expiresAt: now + durationSeconds * 1000,
      remainingExecutions: maxExecutions
    };

    const key = options?.requestFingerprint
      ? `${toolName.trim().toLowerCase()}#${options.requestFingerprint}`
      : toolName.trim().toLowerCase();

    this.leases.set(key, lease);
    return lease;
  }

  public checkAndConsumeElevation(
    toolName: string,
    requestFingerprint?: string
  ): { elevated: boolean; lease?: ElevationLease; reason?: string } {
    const normalized = (toolName || '').trim().toLowerCase();
    let key = requestFingerprint ? `${normalized}#${requestFingerprint}` : normalized;
    let lease = this.leases.get(key);

    if (!lease && requestFingerprint) {
      const toolLease = this.leases.get(normalized);
      if (toolLease && toolLease.scope === 'tool') {
        lease = toolLease;
        key = normalized;
      } else {
        const now = Date.now();
        for (const [k, activeLease] of this.leases.entries()) {
          if (k.startsWith(`${normalized}#`) && activeLease.toolName === normalized && activeLease.expiresAt > now) {
            return { elevated: false, reason: 'REQUEST_FINGERPRINT_MISMATCH' };
          }
        }
      }
    }

    if (!lease) {
      return { elevated: false, reason: 'NO_ACTIVE_LEASE' };
    }

    const now = Date.now();
    if (now > lease.expiresAt) {
      this.leases.delete(key);
      return { elevated: false, reason: 'LEASE_EXPIRED' };
    }

    if (lease.remainingExecutions <= 0) {
      this.leases.delete(key);
      return { elevated: false, reason: 'LEASE_QUOTA_EXHAUSTED' };
    }

    if (lease.requestFingerprint && lease.requestFingerprint !== requestFingerprint) {
      return { elevated: false, reason: 'REQUEST_FINGERPRINT_MISMATCH' };
    }

    lease.remainingExecutions -= 1;
    if (lease.remainingExecutions <= 0) {
      this.leases.delete(key);
    }

    return { elevated: true, lease };
  }

  public revokeLease(toolName: string, requestFingerprint?: string): boolean {
    const normalized = (toolName || '').trim().toLowerCase();
    if (requestFingerprint) {
      return this.leases.delete(`${normalized}#${requestFingerprint}`);
    }
    let deleted = this.leases.delete(normalized);
    for (const k of Array.from(this.leases.keys())) {
      if (k.startsWith(`${normalized}#`)) {
        this.leases.delete(k);
        deleted = true;
      }
    }
    return deleted;
  }

  public listActiveLeases(): ElevationLease[] {
    const now = Date.now();
    const active: ElevationLease[] = [];
    for (const [k, lease] of this.leases.entries()) {
      if (now <= lease.expiresAt && lease.remainingExecutions > 0) {
        active.push(lease);
      } else {
        this.leases.delete(k);
      }
    }
    return active;
  }
}
