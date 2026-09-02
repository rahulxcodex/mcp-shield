import { CanaryManager } from '../../src/security/canary';
import { JITElevationManager } from '../../src/security/jit-elevation';
import { RateLimiter } from '../../src/security/rate-limiter';

describe('Advanced Enterprise Security Features (Phase 2 & 3)', () => {
  describe('CanaryManager (Honeypot & Hallucination Tripwires)', () => {
    let canaryManager: CanaryManager;

    beforeEach(() => {
      canaryManager = new CanaryManager();
    });

    it('generates synthetic honeypot canary tools', () => {
      const canaries = canaryManager.getCanaryTools();
      expect(canaries.length).toBeGreaterThan(0);
      expect(canaries.some(c => c.name.includes('vault_access'))).toBe(true);
      expect(canaries.some(c => c.name.includes('internal_debug_exec'))).toBe(true);
    });

    it('detects attempts to invoke canary tools', () => {
      expect(canaryManager.isCanaryTool('shield_canary_system_vault_access')).toBe(true);
      expect(canaryManager.isCanaryTool('shield_canary_random_exec')).toBe(true);
      expect(canaryManager.isCanaryTool('read_file')).toBe(false);
      expect(canaryManager.isCanaryTool('bash')).toBe(false);
    });

    it('injects canaries into tools list without duplicating', () => {
      const originalTools = [{ name: 'legit_tool', description: 'benign' }];
      const injected = canaryManager.injectCanariesIntoToolsList(originalTools);

      expect(injected.some(t => t.name === 'legit_tool')).toBe(true);
      expect(injected.some(t => t.name === 'shield_canary_system_vault_access')).toBe(true);
      expect(injected.length).toBe(originalTools.length + canaryManager.getCanaryTools().length);
    });

    it('generates random canary tripwire tokens', () => {
      const token1 = canaryManager.generateCanaryToken('aws');
      const token2 = canaryManager.generateCanaryToken('aws');
      expect(token1).toMatch(/^sk-live-canary-aws-[a-f0-9]+$/);
      expect(token1).not.toBe(token2);
    });
  });

  describe('JITElevationManager (Dynamic Human Approvals & Leases)', () => {
    let jitManager: JITElevationManager;

    beforeEach(() => {
      jitManager = new JITElevationManager();
    });

    it('grants a time-bound and quota-bound elevation lease', () => {
      const lease = jitManager.grantLease('bash', 'secops-admin', 'Urgent maintenance', 60, 3);
      expect(lease.toolName).toBe('bash');
      expect(lease.remainingExecutions).toBe(3);
      expect(lease.grantedBy).toBe('secops-admin');
    });

    it('consumes elevation executions correctly until exhausted', () => {
      jitManager.grantLease('exec', 'admin', 'Testing', 60, 2);

      const first = jitManager.checkAndConsumeElevation('exec');
      expect(first.elevated).toBe(true);
      expect(first.lease?.remainingExecutions).toBe(1);

      const second = jitManager.checkAndConsumeElevation('exec');
      expect(second.elevated).toBe(true);
      expect(second.lease?.remainingExecutions).toBe(0);

      const third = jitManager.checkAndConsumeElevation('exec');
      expect(third.elevated).toBe(false);
      expect(third.reason).toBe('NO_ACTIVE_LEASE');
    });

    it('expires leases after the configured time duration', () => {
      jitManager.grantLease('deploy', 'admin', 'Testing expiry', -10, 5); // Already expired
      const check = jitManager.checkAndConsumeElevation('deploy');
      expect(check.elevated).toBe(false);
      expect(check.reason).toBe('LEASE_EXPIRED');
    });

    it('supports explicit lease revocation', () => {
      jitManager.grantLease('terraform', 'admin', 'Plan execution', 300, 5);
      expect(jitManager.revokeLease('terraform')).toBe(true);

      const check = jitManager.checkAndConsumeElevation('terraform');
      expect(check.elevated).toBe(false);
    });
  });

  describe('RateLimiter Semantic Complexity & Token Budgeting', () => {
    it('estimates payload complexity weight proportionally', () => {
      const limiter = new RateLimiter();
      const weight1 = limiter.estimatePayloadWeight('short');
      const weight2 = limiter.estimatePayloadWeight('a'.repeat(400));
      expect(weight1).toBe(2);
      expect(weight2).toBe(100);
    });

    it('blocks runaway payloads that exceed the semantic token budget', () => {
      // 1 call allowed, 200 token budget
      const limiter = new RateLimiter(5, 60000, 10, 200, 500);

      // Call with 50 tokens -> OK
      expect(limiter.checkLimit('test_tool', 'x'.repeat(200))).toBe(true);

      // Call with 300 tokens -> Exceeds 200 budget -> Blocked
      expect(limiter.checkLimit('test_tool', 'y'.repeat(1200))).toBe(false);
    });
  });
});
