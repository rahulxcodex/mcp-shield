export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  failureThreshold?: number; // Consecutive failures to trip (default: 5)
  resetTimeoutMs?: number;   // Time in OPEN state before testing recovery (default: 30,000ms)
  halfOpenMaxProbes?: number;// Successful probes to close (default: 2)
}

export class CircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly halfOpenMaxProbes: number;

  constructor(options?: CircuitBreakerOptions) {
    this.failureThreshold = options?.failureThreshold || 5;
    this.resetTimeoutMs = options?.resetTimeoutMs || 30_000;
    this.halfOpenMaxProbes = options?.halfOpenMaxProbes || 2;
  }

  public getState(): CircuitBreakerState {
    const now = Date.now();
    if (this.state === 'OPEN' && now - this.lastFailureTime > this.resetTimeoutMs) {
      this.state = 'HALF_OPEN';
      this.successCount = 0;
    }
    return this.state;
  }

  public async execute<T>(action: () => Promise<T>, fallback: (err: Error) => T | Promise<T>): Promise<T> {
    const currentState = this.getState();

    if (currentState === 'OPEN') {
      return fallback(new Error('CircuitBreaker is OPEN: Remote service temporarily unavailable'));
    }

    try {
      const result = await action();
      this.onSuccess();
      return result;
    } catch (err: any) {
      this.onFailure();
      return fallback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private onSuccess() {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.halfOpenMaxProbes) {
        this.state = 'CLOSED';
        this.successCount = 0;
      }
    }
  }

  private onFailure() {
    this.lastFailureTime = Date.now();
    this.failureCount++;
    if (this.state === 'HALF_OPEN' || this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  public reset(): void {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}

export const intelServiceCircuitBreaker = new CircuitBreaker({
  failureThreshold: 3,
  resetTimeoutMs: 15_000,
  halfOpenMaxProbes: 2,
});
