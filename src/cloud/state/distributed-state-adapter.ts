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
    const current = (await this.get<number>(key)) || 0;
    const next = current + amount;
    await this.set(key, next, ttlSeconds);
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
      ttlSeconds: windowSeconds
    };
  }

  public clear(): void {
    this.store.clear();
  }
}
