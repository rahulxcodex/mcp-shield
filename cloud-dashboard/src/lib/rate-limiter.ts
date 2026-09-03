/**
 * Sliding Window In-Memory Rate Limiter
 * Provides DDoS, brute-force, and credential stuffing protection for Next.js API endpoints.
 */

interface RateLimitRecord {
  timestamps: number[];
}

class InMemoryRateLimiter {
  private store = new Map<string, RateLimitRecord>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    // Periodic garbage collection every 5 minutes
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    }
  }

  /**
   * Checks if an action is allowed for a given key within windowMs.
   * Returns { allowed: boolean, remaining: number, resetMs: number }
   */
  public check(
    key: string,
    limit: number,
    windowMs: number
  ): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    const windowStart = now - windowMs;

    let record = this.store.get(key);
    if (!record) {
      record = { timestamps: [] };
      this.store.set(key, record);
    }

    // Filter out timestamps outside current window
    record.timestamps = record.timestamps.filter((ts) => ts > windowStart);

    if (record.timestamps.length >= limit) {
      const oldest = record.timestamps[0] || now;
      const resetMs = Math.max(0, oldest + windowMs - now);
      return { allowed: false, remaining: 0, resetMs };
    }

    record.timestamps.push(now);
    return {
      allowed: true,
      remaining: limit - record.timestamps.length,
      resetMs: windowMs,
    };
  }

  private cleanup() {
    const now = Date.now();
    for (const [key, record] of this.store.entries()) {
      // Remove records older than 1 hour
      if (record.timestamps.length === 0 || record.timestamps[record.timestamps.length - 1] < now - 3600 * 1000) {
        this.store.delete(key);
      }
    }
  }
}

export const globalRateLimiter = new InMemoryRateLimiter();

export function getClientIp(req: Request): string {
  // 1. Authoritative Vercel edge proxy header (immune to client-injected spoofing)
  const vercelForwarded = req.headers.get('x-vercel-forwarded-for');
  if (vercelForwarded) {
    return vercelForwarded.split(',')[0].trim();
  }

  // 2. Authoritative real IP set by trusted load balancer
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();

  // 3. Fallback: sanitize standard forwarded chain
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const parts = forwarded.split(',').map(p => p.trim()).filter(Boolean);
    if (parts.length > 0) {
      return parts[parts.length - 1];
    }
  }

  return '127.0.0.1';
}
