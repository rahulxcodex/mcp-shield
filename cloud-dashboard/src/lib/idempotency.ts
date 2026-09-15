/**
 * Payment and Webhook Idempotency Guard
 * Prevents double upgrades, duplicate webhook executions, and race conditions.
 */

import { createAdminSupabaseClient } from './supabase';

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

  /**
   * Async database-backed atomic acquisition for serverless environments.
   * Inserts into `processed_webhook_events` table; fails if key exists within 24h.
   */
  public async acquireAsync(key: string, data: any = {}): Promise<boolean> {
    // First check local memory
    if (!this.acquire(key, data)) {
      return false;
    }

    try {
      const adminClient = createAdminSupabaseClient();
      const { data: inserted, error } = await adminClient
        .from('processed_webhook_events')
        .insert([{ event_id: key, payload: data, processed_at: new Date().toISOString() }])
        .select();

      if (error) {
        // Unique violation code 23505 indicates already processed
        if (error.code === '23505' || error.message.includes('unique')) {
          return false;
        }
      }
    } catch {
      // In case table does not exist or network fails, fallback to local acquire result
    }

    return true;
  }

  public has(key: string): boolean {
    const now = Date.now();
    const existing = this.processed.get(key);
    return Boolean(existing && now - existing.timestamp < 24 * 3600 * 1000);
  }

  public release(key: string): void {
    this.processed.delete(key);
  }
}

export const idempotencyStore = new IdempotencyStore();
