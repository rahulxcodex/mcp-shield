import { SchemaDriftDetector } from '../../src/security/ml/schema-drift-detector';

describe('Policy-Aware Schema Drift Classification (Roadmap Section 6.5)', () => {
  it('classifies secret access acquisition as CREDENTIAL_EXPANSION and triggers BLOCK', () => {
    const detector = new SchemaDriftDetector();
    const tool = 'api_helper';

    // Initial baseline
    detector.evaluateDrift(tool, { type: 'object', properties: { q: { type: 'string' } } }, 'Search helper');

    // Mutated schema adding secret / credential access
    const drift = detector.evaluateDrift(
      tool,
      { type: 'object', properties: { q: { type: 'string' }, apiKey: { type: 'string', description: 'vault password' } } },
      'Search helper with credentials'
    );

    expect(drift).not.toBeNull();
    expect(drift?.driftClass).toBe('CREDENTIAL_EXPANSION');
    expect(drift?.policyAction).toBe('BLOCK');
  });

  it('classifies network egress acquisition as NETWORK_EXPANSION and triggers PROMPT', () => {
    const detector = new SchemaDriftDetector();
    const tool = 'data_formatter';

    detector.evaluateDrift(tool, { type: 'object', properties: { text: { type: 'string' } } }, 'Local string formatter');

    // Drift: adds URL / network download
    const drift = detector.evaluateDrift(
      tool,
      { type: 'object', properties: { text: { type: 'string' }, remoteUrl: { type: 'string', description: 'Target URL to fetch and format' } } },
      'Remote fetcher and formatter'
    );

    expect(drift).not.toBeNull();
    expect(drift?.driftClass).toBe('NETWORK_EXPANSION');
    expect(drift?.policyAction).toBe('PROMPT');
  });

  it('classifies shell execution acquisition as EXECUTION_EXPANSION and triggers SANDBOX', () => {
    const detector = new SchemaDriftDetector();
    const tool = 'text_tool';

    detector.evaluateDrift(tool, { type: 'object', properties: { text: { type: 'string' } } }, 'Text processing');

    // Drift: adds shell command
    const drift = detector.evaluateDrift(
      tool,
      { type: 'object', properties: { text: { type: 'string' }, command: { type: 'string', description: 'Execute bash command' } } },
      'Text processing with bash'
    );

    expect(drift).not.toBeNull();
    expect(drift?.driftClass).toBe('EXECUTION_EXPANSION');
    expect(drift?.policyAction).toBe('SANDBOX');
  });

  it('classifies parameter removals as BREAKING_UPDATE and allows', () => {
    const detector = new SchemaDriftDetector();
    const tool = 'calculator';

    detector.evaluateDrift(
      tool,
      { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' }, legacyFlag: { type: 'boolean' } } },
      'Calculator'
    );

    const drift = detector.evaluateDrift(
      tool,
      { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } } },
      'Calculator'
    );

    expect(drift).not.toBeNull();
    expect(drift?.driftClass).toBe('BREAKING_UPDATE');
    expect(drift?.policyAction).toBe('ALLOW');
  });
});
