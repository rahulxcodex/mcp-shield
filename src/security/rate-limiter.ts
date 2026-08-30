export class RateLimiter {
  private counts = new Map<string, { count: number; firstSeen: number }>();
  
  constructor(private maxCalls: number = 10, private windowMs: number = 60000) {}

  public checkLimit(toolName: string): boolean {
    const now = Date.now();
    let record = this.counts.get(toolName);
    
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
