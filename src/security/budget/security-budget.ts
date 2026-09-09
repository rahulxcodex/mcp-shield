export interface SecurityBudget {
  maxBytes: number;           // e.g. 1MB
  maxDepth: number;           // e.g. 32
  maxAnalysisMs: number;      // e.g. 250ms
  maxGraphNodes: number;      // e.g. 1000
  maxScanningBytes?: number;  // e.g. 10MB
}

export class SecurityBudgetExceededError extends Error {
  public readonly metric: string;
  public readonly limit: number;
  public readonly actual: number;

  constructor(metric: string, limit: number, actual: number) {
    super(`SECURITY_BUDGET_EXCEEDED: ${metric} exceeded limit (${actual} > ${limit})`);
    this.name = 'SecurityBudgetExceededError';
    this.metric = metric;
    this.limit = limit;
    this.actual = actual;
  }
}

export class BudgetTracker {
  private budget: SecurityBudget;
  private startTime: number;
  private bytesConsumed: number = 0;
  private nodesTraversed: number = 0;
  private currentDepth: number = 0;

  constructor(budget?: Partial<SecurityBudget>) {
    this.budget = {
      maxBytes: budget?.maxBytes ?? 1024 * 1024, // 1MB default
      maxDepth: budget?.maxDepth ?? 32,
      maxAnalysisMs: budget?.maxAnalysisMs ?? 250,
      maxGraphNodes: budget?.maxGraphNodes ?? 1000,
      maxScanningBytes: budget?.maxScanningBytes ?? 10 * 1024 * 1024
    };
    this.startTime = Date.now();
  }

  public consumeBytes(bytes: number): void {
    this.bytesConsumed += bytes;
    if (this.bytesConsumed > this.budget.maxBytes) {
      throw new SecurityBudgetExceededError('maxBytes', this.budget.maxBytes, this.bytesConsumed);
    }
  }

  public recordDepth(depth: number): void {
    this.currentDepth = Math.max(this.currentDepth, depth);
    if (depth > this.budget.maxDepth) {
      throw new SecurityBudgetExceededError('maxDepth', this.budget.maxDepth, depth);
    }
  }

  public incrementNodes(count: number = 1): void {
    this.nodesTraversed += count;
    if (this.nodesTraversed > this.budget.maxGraphNodes) {
      throw new SecurityBudgetExceededError('maxGraphNodes', this.budget.maxGraphNodes, this.nodesTraversed);
    }
  }

  public checkDeadline(): void {
    const elapsed = Date.now() - this.startTime;
    if (elapsed > this.budget.maxAnalysisMs) {
      throw new SecurityBudgetExceededError('maxAnalysisMs', this.budget.maxAnalysisMs, elapsed);
    }
  }

  public getStats() {
    return {
      elapsedMs: Date.now() - this.startTime,
      bytesConsumed: this.bytesConsumed,
      nodesTraversed: this.nodesTraversed,
      maxDepthObserved: this.currentDepth
    };
  }
}

export function validatePayloadBounds(
  val: any,
  maxDepth = 32,
  maxKeys = 1000,
  maxStringLength = 65536
): { valid: boolean; reason?: string } {
  let keysCount = 0;
  function walk(curr: any, depth: number): boolean {
    if (depth > maxDepth) return false;
    if (curr === null || typeof curr !== 'object') {
      if (typeof curr === 'string' && curr.length > maxStringLength) {
        return false;
      }
      return true;
    }
    const keys = Object.keys(curr);
    keysCount += keys.length;
    if (keysCount > maxKeys) return false;
    for (const k of keys) {
      if (!walk(curr[k], depth + 1)) return false;
    }
    return true;
  }
  if (!walk(val, 1)) {
    return { valid: false, reason: `PAYLOAD_BOUNDS_EXCEEDED: Exceeded max depth (${maxDepth}), keys (${maxKeys}), or string length (${maxStringLength})` };
  }
  return { valid: true };
}
