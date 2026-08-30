import { PolicyEngine, ShieldConfig } from '../../src/security/policy-engine';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import * as path from 'path';
import * as os from 'os';

const actualFs = jest.requireActual('fs');
const actualYaml = jest.requireActual('js-yaml');

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  let tempConfigFile: string;
  
  const mockConfig: ShieldConfig = {
    version: '1.0',
    profile: 'test',
    redaction: { enabled: true, maskStyle: 'uuid', highEntropyCheck: false, entropyThreshold: 4.2 },
    sandbox: { cowEnabled: true, cowStagingDir: '/tmp/cow', autoCommitOnApproval: false },
    egress: { enabled: true, allowMode: 'allow', allowPrivateNetworks: true, blockLoopback: false, blockLinkLocal: false, blockMetadataEndpoints: false, blockedDomains: ['*.evil.com'] },
    audit: { enabled: true, logDir: '/tmp/logs', tamperProofHashing: true },
    rules: [
      {
        id: '1',
        name: 'Block dangerous filesystem access',
        priority: 100,
        targetTools: ['fs_*', 'read_file', 'write_file'],
        riskLevel: 'CRITICAL',
        action: 'block',
        matchers: {
          pathMatches: {
            forbiddenPaths: ['/etc/**', '/var/log/**']
          }
        }
      },
      {
        id: '2',
        name: 'Require approval for shell',
        priority: 90,
        targetTools: ['run_command'],
        riskLevel: 'HIGH',
        action: 'sandbox'
      },
      {
        id: '3',
        name: 'Allow safe filesystem access',
        priority: 50,
        targetTools: ['fs_*', 'read_file', 'write_file'],
        riskLevel: 'LOW',
        action: 'allow'
      }
    ]
  };

  beforeEach(() => {
    engine = new PolicyEngine(mockConfig);
    engine.start();
  });

  afterEach(() => {
    engine.close();
  });

  it('should load config correctly', () => {
    expect(engine.getConfig().profile).toBe('test');
    expect(engine.getConfig().rules.length).toBe(3);
  });

  it('should evaluate tool call and return matching action', () => {
    const result = engine.evaluate({ toolName: 'run_command', args: { cmd: 'ls' }, evidence: [] });
    expect(result.decision).toBe('sandbox');
    expect(result.ruleId).toBe('2');
  });

  it('should evaluate wildcard tool target and allow safe paths', () => {
    const result = engine.evaluate({ toolName: 'fs_read', args: { file: '/tmp/test.txt' }, evidence: [] });
    expect(result.decision).toBe('allow');
  });

  it('should block forbidden paths using path matcher', () => {
    const result = engine.evaluate({ toolName: 'read_file', args: { path: '/etc/passwd' }, evidence: [] });
    expect(result.decision).toBe('block');
    expect(result.ruleId).toBe('1');
  });
  
  it('should block wildcard forbidden paths', () => {
    const result = engine.evaluate({ toolName: 'fs_write', args: { filename: '/var/log/app.log' }, evidence: [] });
    expect(result.decision).toBe('block');
    expect(result.ruleId).toBe('1');
  });

  it('should block relative path etc/passwd without leading slash', () => {
    const result = engine.evaluate({ toolName: 'read_file', args: { path: 'etc/passwd' }, evidence: [] });
    expect(result.decision).toBe('block');
  });

  it('should block uppercase /ETC/passwd path', () => {
    const result = engine.evaluate({ toolName: 'read_file', args: { path: '/ETC/passwd' }, evidence: [] });
    expect(result.decision).toBe('block');
  });

  it('should block traversal paths like /tmp/../etc/passwd', () => {
    const result = engine.evaluate({ toolName: 'read_file', args: { path: '/tmp/../etc/passwd' }, evidence: [] });
    expect(result.decision).toBe('block');
  });

  it('should block Windows backslash and drive-prefixed paths matching forbidden rules', () => {
    const res1 = engine.evaluate({ toolName: 'read_file', args: { path: 'C:\\etc\\passwd' }, evidence: [] });
    expect(res1.decision).toBe('block');

    const res2 = engine.evaluate({ toolName: 'read_file', args: { path: 'C:/var/log/system.log' }, evidence: [] });
    expect(res2.decision).toBe('block');
  });

  it('should allow legitimate paths that merely contain etc as substring', () => {
    const result = engine.evaluate({ toolName: 'read_file', args: { path: '/home/dev/etc-configs/notes.txt' }, evidence: [] });
    expect(result.decision).toBe('allow');
  });

  it('should close file watcher on close()', () => {
    expect(() => engine.close()).not.toThrow();
  });

  it('should default to allow if no rules match', () => {
    const result = engine.evaluate({ toolName: 'unknown_tool', args: { foo: 'bar' }, evidence: [] });
    // Default hardened mode now blocks unknown tools
    expect(result.decision).toBe('block');
  });
});
