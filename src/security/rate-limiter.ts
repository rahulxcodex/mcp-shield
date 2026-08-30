export class RateLimiter {
  private counts = new Map<string, { count: number; firstSeen: number }>();
  private readonly MAX_TRACKED_TOOLS = 1000;
  
  constructor(private maxCalls: number = 15, private windowMs: number = 60000) {}

  public checkLimit(toolName: string): boolean {
    const now = Date.now();
    let record = this.counts.get(toolName);
    
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
      this.counts.set(toolName, { count: 1, firstSeen: now });
      return true; // within limit
    }
    
    record.count++;
    if (record.count > this.maxCalls) {
      return false; // limit exceeded
    }
    
    return true; // within limit
  }
}
