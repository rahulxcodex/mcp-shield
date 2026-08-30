export class RateLimiter {
  private counts = new Map<string, { count: number; firstSeen: number }>();
  private globalCount = 0;
  private globalWindowStart = Date.now();
  private readonly MAX_TRACKED_TOOLS = 1000;
  
  constructor(
    private maxCalls: number = 15,
    private windowMs: number = 60000,
    private maxGlobalCalls: number = 120
  ) {}

  public checkLimit(toolName: string): boolean {
    const now = Date.now();
    const normalizedName = (toolName || '').trim().toLowerCase();

    // 1. Global throughput ceiling check
    if (now - this.globalWindowStart > this.windowMs) {
      this.globalCount = 0;
      this.globalWindowStart = now;
    }
    this.globalCount++;
    if (this.globalCount > this.maxGlobalCalls) {
      return false; // Global throughput ceiling exceeded
    }

    // 2. Per-tool rate limit check
    let record = this.counts.get(normalizedName);
    
    // Prune stale records if map exceeds capacity
    if (this.counts.size > this.MAX_TRACKED_TOOLS) {
      for (const [key, val] of this.counts.entries()) {
        if (now - val.firstSeen > this.windowMs) {
          this.counts.delete(key);
        }
      }
      if (this.counts.size > this.MAX_TRACKED_TOOLS) {
        const oldestKey = this.counts.keys().next().value;
        if (oldestKey) this.counts.delete(oldestKey);
      }
    }

    if (!record || (now - record.firstSeen > this.windowMs)) {
      this.counts.set(normalizedName, { count: 1, firstSeen: now });
      return true; // within limit
    }
    
    record.count++;
    if (record.count > this.maxCalls) {
      return false; // limit exceeded
    }
    
    return true; // within limit
  }
}
