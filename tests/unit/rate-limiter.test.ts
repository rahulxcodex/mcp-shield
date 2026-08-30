import { RateLimiter } from '../../src/security/rate-limiter';

describe('RateLimiter', () => {
  it('should enforce case-insensitive rate limiting on tool names', () => {
    const rl = new RateLimiter(2, 60000, 100);
    expect(rl.checkLimit('bash')).toBe(true);
    expect(rl.checkLimit('BASH')).toBe(true);
    expect(rl.checkLimit('Bash')).toBe(false); // 3rd call exceeded maxCalls (2)
  });

  it('should enforce global throughput ceiling', () => {
    const rl = new RateLimiter(10, 60000, 3); // max 3 calls globally
    expect(rl.checkLimit('tool_1')).toBe(true);
    expect(rl.checkLimit('tool_2')).toBe(true);
    expect(rl.checkLimit('tool_3')).toBe(true);
    expect(rl.checkLimit('tool_4')).toBe(false); // 4th call globally exceeded maxGlobalCalls (3)
  });
});
