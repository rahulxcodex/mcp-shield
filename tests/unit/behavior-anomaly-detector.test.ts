import { BehaviorAnomalyDetector } from '../../src/security/ml/models/behavior-anomaly-detector';

describe('Model C: Behavioral Anomaly Detection (Roadmap Section 4)', () => {
  it('identifies standard transitions as normal based on baseline', () => {
    const detector = new BehaviorAnomalyDetector({
      knownTools: ['read_file', 'grep_code'],
      knownTransitions: [['read_file', 'grep_code']],
      knownCapabilities: ['filesystemRead']
    });

    const result = detector.evaluateAction({
      lastTool: 'read_file',
      currentTool: 'grep_code',
      currentCapabilities: ['filesystemRead']
    });

    expect(result.isAnomalous).toBe(false);
    expect(result.anomalyScore).toBe(0.0);
    expect(result.deviations.length).toBe(0);
  });

  it('flags unobserved capabilities and abrupt privilege escalation leaps', () => {
    const detector = new BehaviorAnomalyDetector({
      knownTools: ['read_file', 'list_dir'],
      knownTransitions: [['read_file', 'list_dir']],
      knownCapabilities: ['filesystemRead'],
      highPrivilegeTools: ['exec_bash']
    });

    const result = detector.evaluateAction({
      lastTool: 'read_file',
      currentTool: 'exec_bash',
      currentCapabilities: ['filesystemRead', 'shellExecution', 'networkAccess'],
      destination: 'external.evil.com'
    });

    expect(result.isAnomalous).toBe(true);
    expect(result.anomalyScore).toBeGreaterThanOrEqual(0.7);
    expect(result.deviations.some(d => d.type === 'NEW_CAPABILITY')).toBe(true);
    expect(result.deviations.some(d => d.type === 'PRIVILEGE_TRANSITION')).toBe(true);
    expect(result.deviations.some(d => d.type === 'NEW_DESTINATION')).toBe(true);
    expect(result.evidence).toBeDefined();
    expect(result.evidence?.category).toBe('ANOMALOUS_BEHAVIOR');
  });
});
