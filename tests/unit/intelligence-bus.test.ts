import { SecurityIntelligenceBus, SecuritySignal } from '../../src/security/intelligence/intelligence-bus';

describe('SecurityIntelligenceBus & Signal Fusion (Roadmap Section 7.2)', () => {
  it('allows pub/sub routing of typed security signals', () => {
    const bus = new SecurityIntelligenceBus();
    const received: SecuritySignal[] = [];

    bus.subscribe('SSRF', (sig) => received.push(sig));

    bus.publish({
      signalId: 'sig-1',
      source: 'egress-engine',
      category: 'SSRF',
      severity: 0.95,
      confidence: 1.0,
      timestamp: Date.now(),
      scope: 'request',
      evidence: { host: '169.254.169.254' }
    });

    expect(received).toHaveLength(1);
    expect(received[0].category).toBe('SSRF');
  });

  it('enforces deterministic hard block precedence over low ML risk', () => {
    const signals: SecuritySignal[] = [
      {
        signalId: 'ml-1',
        source: 'tabular-risk-model',
        category: 'BEHAVIOR_ANOMALY',
        severity: 0.2, // Low ML risk
        confidence: 0.8,
        timestamp: Date.now(),
        scope: 'request',
        evidence: {}
      },
      {
        signalId: 'det-1',
        source: 'deterministic-ast-firewall',
        category: 'COMMAND_INJECTION',
        severity: 0.99,
        confidence: 1.0,
        timestamp: Date.now(),
        scope: 'request',
        evidence: { pattern: 'rm -rf /' },
        hardBlockCandidate: true
      }
    ];

    const fusion = SecurityIntelligenceBus.fuseSignals(signals);
    expect(fusion.recommendedAction).toBe('BLOCK');
    expect(fusion.deterministicBlockTriggered).toBe(true);
    expect(fusion.enforcementSource).toBe('deterministic');
    expect(fusion.compositeRiskScore).toBe(1.0);
  });

  it('evaluates attack graph kill-chain signals into composite BLOCK', () => {
    const signals: SecuritySignal[] = [
      {
        signalId: 'chain-1',
        source: 'attack-path-engine',
        category: 'ATTACK_PATH',
        severity: 0.94,
        confidence: 0.95,
        timestamp: Date.now(),
        scope: 'session',
        evidence: { sequence: ['read_file', 'curl'] }
      }
    ];

    const fusion = SecurityIntelligenceBus.fuseSignals(signals);
    expect(fusion.recommendedAction).toBe('BLOCK');
    expect(fusion.enforcementSource).toBe('composite');
  });

  it('uses advisory ML signals to trigger PROMPT or SANDBOX', () => {
    const promptSignals: SecuritySignal[] = [
      {
        signalId: 'ml-suspicious',
        source: 'text-security-classifier',
        category: 'PROMPT_INJECTION',
        severity: 0.65,
        confidence: 0.85,
        timestamp: Date.now(),
        scope: 'request',
        evidence: {}
      }
    ];

    const fusion = SecurityIntelligenceBus.fuseSignals(promptSignals);
    expect(fusion.recommendedAction).toBe('PROMPT');
    expect(fusion.compositeRiskScore).toBe(0.65);
  });

  it('compounds multiple concurrent advisory signals into elevated Bayesian posterior risk', () => {
    const multiSignals: SecuritySignal[] = [
      {
        signalId: 'sig-ml-1',
        source: 'tabular-risk-model',
        category: 'COMPLEXITY_SPIKE',
        severity: 0.60,
        confidence: 0.90,
        timestamp: Date.now(),
        scope: 'request',
        evidence: {}
      },
      {
        signalId: 'sig-ml-2',
        source: 'text-security-classifier',
        category: 'PROMPT_INJECTION',
        severity: 0.60,
        confidence: 0.90,
        timestamp: Date.now(),
        scope: 'request',
        evidence: {}
      }
    ];

    const fusion = SecurityIntelligenceBus.fuseSignals(multiSignals);
    // Bayesian Noisy-OR: 1 - (1 - 0.54)*(1 - 0.54) = 1 - 0.2116 = 0.7884 -> exceeds 0.75 threshold
    expect(fusion.compositeRiskScore).toBeGreaterThanOrEqual(0.75);
    expect(fusion.recommendedAction).toBe('BLOCK');
    expect(fusion.enforcementSource).toBe('composite');
  });
});
