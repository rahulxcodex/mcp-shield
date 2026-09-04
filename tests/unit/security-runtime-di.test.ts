import { SecurityRuntime, InMemorySessionStore, InMemoryBehaviorStore, InMemoryReputationStore, InMemoryThreatCorpusStore } from '../../src/core/runtime/security-runtime';

describe('SecurityRuntime & Dependency Injection (Roadmap Section 10)', () => {
  it('allows multiple independent runtime instances without shared mutable state', () => {
    const runtime1 = new SecurityRuntime();
    const runtime2 = new SecurityRuntime();

    runtime1.threatStore.addPattern('malicious-pattern-xyz');
    expect(runtime1.threatStore.hasPattern('malicious-pattern-xyz')).toBe(true);
    expect(runtime2.threatStore.hasPattern('malicious-pattern-xyz')).toBe(false);

    runtime1.reputationStore.updateReputation('agent-001', -0.5);
    expect(runtime1.reputationStore.getReputation('agent-001')).toBe(0.5);
    expect(runtime2.reputationStore.getReputation('agent-001')).toBe(1.0);
  });

  it('enforces isolated session lifecycles and clean resets', () => {
    const runtime = new SecurityRuntime();
    runtime.sessionStore.set('sess-1', { active: true });
    expect(runtime.sessionStore.count()).toBe(1);

    runtime.reset();
    expect(runtime.sessionStore.count()).toBe(0);
  });

  it('tracks behavior invocations with rolling bounds', () => {
    const behaviorStore = new InMemoryBehaviorStore(5);
    for (let i = 0; i < 10; i++) {
      behaviorStore.recordInvocation('bash', { index: i });
    }

    const history = behaviorStore.getHistory('bash');
    expect(history.length).toBe(5);
    expect(history[4].index).toBe(9);
  });
});
