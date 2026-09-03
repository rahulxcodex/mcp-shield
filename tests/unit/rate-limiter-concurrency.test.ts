import { RateLimiter } from '../../src/security/rate-limiter';

describe('RateLimiter Atomic Check-and-Reserve & Concurrency Suite', () => {
  it('RL-ATOMIC-01: Rejected tool calls must NEVER increment global counters', () => {
    // Max 2 calls per window, max 5 global calls
    const limiter = new RateLimiter(2, 60000, 5);

    // Call 1 & 2: Admitted
    expect(limiter.checkLimit('bash')).toBe(true);
    expect(limiter.checkLimit('bash')).toBe(true);
    expect(limiter.getGlobalCount()).toBe(2);
    expect(limiter.getToolCount('bash')).toBe(2);

    // Call 3: Exceeds per-tool limit (2), must be rejected
    expect(limiter.checkLimit('bash')).toBe(false);
    // CRITICAL SECURITY INVARIANT: Blocked call MUST NOT increment global count!
    expect(limiter.getGlobalCount()).toBe(2);
    expect(limiter.getToolCount('bash')).toBe(2);

    // Send 10 more rejected calls
    for (let i = 0; i < 10; i++) {
      expect(limiter.checkLimit('bash')).toBe(false);
    }
    expect(limiter.getGlobalCount()).toBe(2);

    // Legitimate distinct tool call should still be admitted because global budget was NOT exhausted!
    expect(limiter.checkLimit('read_file')).toBe(true);
    expect(limiter.getGlobalCount()).toBe(3);
    expect(limiter.getToolCount('read_file')).toBe(1);
  });

  it('RL-ATOMIC-02: Rejected token-budget overruns do NOT consume token weight', () => {
    // maxCalls: 10, windowMs: 60000, maxGlobalCalls: 100, maxTokenBudgetPerTool: 50, maxGlobalTokenBudget: 100
    const limiter = new RateLimiter(10, 60000, 100, 50, 100);

    const normalPayload = { query: 'short query' }; // ~4 tokens
    expect(limiter.checkLimit('search', normalPayload)).toBe(true);
    const initialWeight = limiter.getGlobalTokenWeight();
    expect(initialWeight).toBeGreaterThan(0);

    // Gigantic payload that exceeds per-tool budget
    const oversizedPayload = { data: 'A'.repeat(5000) }; // ~1250 tokens
    expect(limiter.checkLimit('search', oversizedPayload)).toBe(false);

    // Token weight must remain unchanged!
    expect(limiter.getGlobalTokenWeight()).toBe(initialWeight);
  });

  it('RL-ATOMIC-03: Concurrent simulated invocations maintain exact atomic counter bounds', async () => {
    const maxGlobal = 15;
    const limiter = new RateLimiter(5, 60000, maxGlobal);

    // Dispatch 30 parallel tool requests across 6 tools
    const tools = ['t1', 't2', 't3', 't4', 't5', 't6'];
    const results: boolean[] = [];

    const tasks: Promise<void>[] = [];
    for (let i = 0; i < 30; i++) {
      const tool = tools[i % tools.length];
      tasks.push(
        (async () => {
          const admitted = limiter.checkLimit(tool);
          results.push(admitted);
        })()
      );
    }

    await Promise.all(tasks);

    const admittedCount = results.filter((r) => r === true).length;
    const rejectedCount = results.filter((r) => r === false).length;

    expect(admittedCount).toBeLessThanOrEqual(maxGlobal);
    expect(limiter.getGlobalCount()).toBe(admittedCount);
    expect(admittedCount + rejectedCount).toBe(30);
  });
});
