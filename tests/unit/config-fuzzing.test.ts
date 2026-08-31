import { PolicyEngine, ShieldConfig } from '../../src/security/policy-engine';

describe('Adversarial Configuration Fuzzing & Resilience Suite (Item 50)', () => {
  it('resiliently handles malformed, partial, or adversarial configuration shapes without crashing', () => {
    const adversarialConfigs: any[] = [
      {},
      { version: '1.0' },
      { rules: null },
      { rules: [{ id: '1', action: 'allow' }] },
      { rules: [{ id: '2', priority: 'high', riskLevel: 'CRITICAL', action: 'allow' }] },
      { egress: { enabled: true, blockedDomains: null } },
      { egress: { enabled: 'invalid_boolean' } },
      { sandbox: { cowEnabled: 'true_string' } },
      { redaction: { entropyThreshold: -10 } },
      { rules: [{ targetTools: ['[a-z+*invalid_regex'] }] }
    ];

    for (const conf of adversarialConfigs) {
      expect(() => {
        const engine = new PolicyEngine(conf as ShieldConfig);
        const res = engine.evaluate({
          toolName: 'any_tool',
          args: { cmd: 'ls' },
          evidence: []
        });
        expect(res).toBeDefined();
        expect(typeof res.decision).toBe('string');
      }).not.toThrow();
    }
  });

  it('enforces that CRITICAL risk rules cannot map to allow without explicit unsafe overrides', () => {
    const dangerousConfig: any = {
      rules: [
        {
          id: 'crit-allow',
          name: 'Dangerous Critical Allow',
          priority: 100,
          targetTools: ['*'],
          riskLevel: 'CRITICAL',
          action: 'allow'
        }
      ]
    };

    const engine = new PolicyEngine(dangerousConfig as ShieldConfig);
    const result = engine.evaluate({
      toolName: 'destructive_tool',
      args: {},
      evidence: []
    });

    // Invariant: should downgrade/block CRITICAL rule when action is allow
    expect(result.decision).toBe('block');
  });
});
