/**
 * Distributed State & Rate Limiting Adapter for Serverless & Multi-Instance Environments
 * Supports horizontal scaling across Vercel Functions / Docker containers.
 */

export interface RateLimitResult {
  allowed: boolean;
  current: number;
  remaining: number;
  ttlSeconds: number;
}

export interface DistributedStateStore {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  increment(key: string, amount?: number, ttlSeconds?: number): Promise<number>;
  checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
  consumeNonce(nonce: string, ttlSeconds: number): Promise<boolean>;
}

export class MemoryDistributedStateStore implements DistributedStateStore {
  private store: Map<string, { value: unknown; expiresAt?: number }> = new Map();

  public async get<T>(key: string): Promise<T | null> {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry.value as T;
  }

  public async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
  }

  public async delete(key: string): Promise<boolean> {
    return this.store.delete(key);
  }

  public async increment(key: string, amount: number = 1, ttlSeconds?: number): Promise<number> {
    this.cleanExpired();
    const current = (await this.get<number>(key)) || 0;
    const next = current + amount;
    await this.set(key, next, ttlSeconds);
    return next;
  }

  public async checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    this.cleanExpired();
    const count = await this.increment(key, 1, windowSeconds);
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);

    return {
      allowed,
      current: count,
      remaining,
      ttlSeconds: windowSeconds
    };
  }

  /**
   * Atomically checks and reserves a replay nonce.
   * Returns true if the nonce is fresh (consumed), false if already seen (replay detected).
   */
  public async consumeNonce(nonce: string, ttlSeconds: number = 300): Promise<boolean> {
    this.cleanExpired();
    const key = `nonce:${nonce}`;
    const existing = await this.get<boolean>(key);
    if (existing) {
      return false; // Replay detected
    }
    await this.set(key, true, ttlSeconds);
    return true; // Fresh nonce consumed
  }

  /**
   * Periodic eviction sweep to prevent memory leak from stale keys.
   */
  public cleanExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.store.delete(key);
      }
    }
  }

  public clear(): void {
    this.store.clear();
  }
}

/**
 * Distributed state store adapter using Upstash / Redis REST API.
 * High-performance, zero-native-dependency adapter for serverless / edge environments.
 */
export class UpstashRedisDistributedStateStore implements DistributedStateStore {
  private url: string;
  private token: string;

  constructor(url: string, token: string) {
    this.url = url.replace(/\/$/, '');
    this.token = token;
  }

  private async execute(command: string[]): Promise<any> {
    const res = await fetch(`${this.url}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(command),
    });
    if (!res.ok) {
      throw new Error(`Upstash Redis error: ${res.statusText}`);
    }
    const data = await res.json();
    return data.result;
  }

  public async get<T>(key: string): Promise<T | null> {
    try {
      const raw = await this.execute(['GET', key]);
      if (raw === null || raw === undefined) return null;
      try {
        return JSON.parse(raw);
      } catch {
        return raw as T;
      }
    } catch {
      return null;
    }
  }

  public async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    if (ttlSeconds && ttlSeconds > 0) {
      await this.execute(['SET', key, serialized, 'EX', ttlSeconds.toString()]);
    } else {
      await this.execute(['SET', key, serialized]);
    }
  }

  public async delete(key: string): Promise<boolean> {
    try {
      const count = await this.execute(['DEL', key]);
      return Number(count) > 0;
    } catch {
      return false;
    }
  }

  public async increment(key: string, amount: number = 1, ttlSeconds?: number): Promise<number> {
    let next: number;
    if (amount === 1) {
      next = Number(await this.execute(['INCR', key]));
    } else {
      next = Number(await this.execute(['INCRBY', key, amount.toString()]));
    }
    if (ttlSeconds && next === amount) {
      await this.execute(['EXPIRE', key, ttlSeconds.toString()]);
    }
    return next;
  }

  public async checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const count = await this.increment(key, 1, windowSeconds);
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);
    return {
      allowed,
      current: count,
      remaining,
      ttlSeconds: windowSeconds,
    };
  }

  public async consumeNonce(nonce: string, ttlSeconds: number = 300): Promise<boolean> {
    const key = `nonce:${nonce}`;
    try {
      const result = await this.execute(['SET', key, '1', 'EX', ttlSeconds.toString(), 'NX']);
      return result === 'OK';
    } catch {
      return false;
    }
  }
}

/**
 * Global distributed state singleton.
 * Uses shared Redis / Upstash if configured; falls back to bounded in-memory store.
 */
class DistributedStateManager {
  private static instance: DistributedStateStore;

  public static getStore(): DistributedStateStore {
    if (!DistributedStateManager.instance) {
      const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
      const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;
      if (upstashUrl && upstashToken) {
        DistributedStateManager.instance = new UpstashRedisDistributedStateStore(upstashUrl, upstashToken);
      } else {
        DistributedStateManager.instance = new MemoryDistributedStateStore();
      }
    }
    return DistributedStateManager.instance;
  }

  public static setStore(store: DistributedStateStore): void {
    DistributedStateManager.instance = store;
  }
}

export const getDistributedStateStore = (): DistributedStateStore => DistributedStateManager.getStore();
