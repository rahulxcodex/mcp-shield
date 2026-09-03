/**
 * Payment and Webhook Idempotency Guard
 * Prevents double upgrades, duplicate webhook executions, and race conditions.
 */

interface IdempotentRecord {
  timestamp: number;
  data: any;
}

class IdempotencyStore {
  private processed = new Map<string, IdempotentRecord>();

  /**
   * Tries to acquire a lock / mark an operation as processed.
   * Returns true if newly acquired, false if already processed.
   */
  public acquire(key: string, data: any = {}): boolean {
    const now = Date.now();
    const existing = this.processed.get(key);
    // Retain idempotency window for 24 hours
    if (existing && now - existing.timestamp < 24 * 3600 * 1000) {
      return false; // Already processed
    }

    this.processed.set(key, { timestamp: now, data });
    return true;
  }

  public has(key: string): boolean {
    const now = Date.now();
    const existing = this.processed.get(key);
    return Boolean(existing && now - existing.timestamp < 24 * 3600 * 1000);
  }
}

export const idempotencyStore = new IdempotencyStore();
