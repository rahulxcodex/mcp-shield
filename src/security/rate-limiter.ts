export class RateLimiter {
  private counts = new Map<string, { count: number; tokenWeight: number; firstSeen: number }>();
  private globalCount = 0;
  private globalTokenWeight = 0;
  private globalWindowStart = Date.now();
  private readonly MAX_TRACKED_TOOLS = 1000;
  
  constructor(
    private maxCalls: number = 15,
    private windowMs: number = 60000,
    private maxGlobalCalls: number = 120,
    private maxTokenBudgetPerTool: number = 50000,
    private maxGlobalTokenBudget: number = 200000
  ) {}

  public estimatePayloadWeight(payload: any): number {
    if (!payload) return 1;
    let str: string;
    try {
      str = typeof payload === 'string' ? payload : JSON.stringify(payload);
    } catch {
      return 1;
    }
    // Standard rule: ~4 chars per token plus base complexity overhead
    return Math.max(1, Math.ceil(str.length / 4));
  }

  public checkLimit(toolName: string, payload?: any): boolean {
    const now = Date.now();
    const normalizedName = (toolName || '').trim().toLowerCase();
    const weight = payload ? this.estimatePayloadWeight(payload) : 1;

    // 1. Global throughput & token budget check
    if (now - this.globalWindowStart > this.windowMs) {
      this.globalCount = 0;
      this.globalTokenWeight = 0;
      this.globalWindowStart = now;
    }
    this.globalCount++;
    this.globalTokenWeight += weight;

    if (this.globalCount > this.maxGlobalCalls || this.globalTokenWeight > this.maxGlobalTokenBudget) {
      return false; // Global throughput ceiling or semantic token budget exceeded
    }

    // 2. Per-tool rate limit & complexity budget check
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
      this.counts.set(normalizedName, { count: 1, tokenWeight: weight, firstSeen: now });
      return true; // within limit
    }
    
    record.count++;
    record.tokenWeight += weight;

    if (record.count > this.maxCalls || record.tokenWeight > this.maxTokenBudgetPerTool) {
      return false; // limit or semantic token budget exceeded
    }
    
    return true; // within limit
  }
}
