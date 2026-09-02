import { PolicyEngine, ShieldConfigSchema } from '../../src/security/policy-engine';
import { ConfigLoader } from '../../src/security/config';

describe('Dual-Tier Policy Engine & Mode Configuration', () => {
  it('should parse mode and onError from ShieldConfigSchema', () => {
    const config = ShieldConfigSchema.parse({
      version: '1.0',
      profile: 'test',
      mode: 'audit',
      onError: 'block',
      redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.5 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: true },
      egress: { enabled: true, allowMode: 'allow' },
      rules: [
        { id: 'rule-1', name: 'Test Rule', priority: 10, riskLevel: 'LOW', action: 'allow' }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true, siemFormat: 'json' }
    });

    expect(config.mode).toBe('audit');
    expect(config.onError).toBe('block');
    expect(config.audit.siemFormat).toBe('json');
  });

  it('should default mode to enforce and onError to block', () => {
    const engine = new PolicyEngine();
    expect(engine.getMode()).toBe('enforce');
    expect(engine.getOnError()).toBe('block');
  });

  it('should support audit mode without altering policy evaluation output logic', () => {
    const auditEngine = new PolicyEngine({
      version: '1.0',
      profile: 'shadow',
      mode: 'audit',
      onError: 'bypass',
      redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.5 },
      sandbox: { cowEnabled: false, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: false },
      egress: { enabled: false, allowMode: 'allow', allowPrivateNetworks: false, blockLoopback: true, blockLinkLocal: true, blockMetadataEndpoints: true },
      rules: [
        { id: 'block-shell', name: 'Block Shell', priority: 100, targetTools: ['bash'], riskLevel: 'CRITICAL', action: 'block' }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    });

    expect(auditEngine.getMode()).toBe('audit');
    expect(auditEngine.getOnError()).toBe('bypass');

    const result = auditEngine.evaluate({
      toolName: 'bash',
      args: { command: 'echo hello' },
      evidence: []
    });

    // Invariant: evaluate() returns true policy evaluation (block), allowing ProxyServer to handle shadow recording
    expect(result.decision).toBe('block');
    expect(result.ruleId).toBe('block-shell');
  });

  it('should load hardened profile with enforce mode and block on error', () => {
    const hardened = ConfigLoader.getHardenedProfile();
    expect(hardened.mode).toBe('enforce');
    expect(hardened.onError).toBe('block');
  });
});
