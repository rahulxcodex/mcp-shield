import { SecurityReplayEngine, ReplayInputEvent } from '../../src/security/replay/security-replay-engine';

describe('SecurityReplayEngine (Roadmap Section 7.6)', () => {
  it('replays historical events and identifies decision diffs and latency deltas', async () => {
    const replayEngine = new SecurityReplayEngine();

    const sampleEvents: ReplayInputEvent[] = [
      {
        eventId: 'evt-benign-1',
        timestamp: Date.now() - 10000,
        toolName: 'read_doc',
        rawArgs: { path: 'docs/guide.md' },
        originalDecision: { action: 'ALLOW', riskScore: 0.05 },
        originalLatencyUs: 150,
        groundTruthLabel: 'BENIGN'
      },
      {
        eventId: 'evt-attack-unblocked-before',
        timestamp: Date.now() - 5000,
        toolName: 'shell',
        rawArgs: { command: 'cat /etc/passwd; rm -rf /' },
        // Old detector missed this or allowed it:
        originalDecision: { action: 'ALLOW', riskScore: 0.1 },
        originalLatencyUs: 180,
        groundTruthLabel: 'MALICIOUS'
      }
    ];

    const report = await replayEngine.replayEvents(sampleEvents);

    expect(report.totalEvents).toBe(2);
    // The malicious event should now be blocked by the upgraded pipeline
    expect(report.decisionsChanged).toBeGreaterThanOrEqual(1);
    expect(report.newBlocksCount).toBe(1);
    expect(report.falsePositiveDelta).toBe(0); // Did not penalize benign event

    const attackComparison = report.comparisons.find((c) => c.eventId === 'evt-attack-unblocked-before');
    expect(attackComparison?.oldAction).toBe('ALLOW');
    expect(attackComparison?.newAction).toBe('BLOCK');
    expect(attackComparison?.riskDelta).toBeGreaterThan(0);
    expect(attackComparison?.actionChanged).toBe(true);
  });
});
