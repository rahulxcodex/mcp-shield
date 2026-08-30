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
    egress: { enabled: true, blockedDomains: ['*.evil.com'] },
    audit: { enabled: true, logDir: '/tmp/logs', tamperProofHashing: true },
    rules: [
      {
        id: '1',
        name: 'Block dangerous filesystem access',
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
        targetTools: ['run_command'],
        riskLevel: 'HIGH',
        action: 'sandbox'
      }
    ]
  };

  beforeAll(() => {
    tempConfigFile = path.join(os.tmpdir(), `policy-test-${Date.now()}-${Math.random().toString(36).slice(2)}.yaml`);
    fs.writeFileSync(tempConfigFile, yaml.dump(mockConfig), 'utf8');
  });

  afterAll(() => {
    if (fs.existsSync(tempConfigFile)) {
      try { fs.unlinkSync(tempConfigFile); } catch {}
    }
  });

  beforeEach(() => {
    engine = new PolicyEngine(tempConfigFile);
  });

  afterEach(() => {
    engine.close();
  });

  it('should load config correctly', () => {
    engine.loadConfig();
    expect(engine.getConfig().profile).toBe('test');
    expect(engine.getConfig().rules.length).toBe(2);
  });

  it('should throw error if config not found', () => {
    const nonExistentEngine = new PolicyEngine('/non/existent/path/shield.yaml');
    expect(() => nonExistentEngine.loadConfig()).toThrow('Config file not found');
  });

  it('should evaluate tool call and return matching action', () => {
    const result = engine.evaluateToolCall('run_command', { cmd: 'ls' });
    expect(result.decision).toBe('sandbox');
    expect(result.ruleId).toBe('2');
  });

  it('should evaluate wildcard tool target and allow safe paths', () => {
    const result = engine.evaluateToolCall('fs_read', { file: '/tmp/test.txt' });
    expect(result.decision).toBe('allow');
  });

  it('should block forbidden paths using path matcher', () => {
    const result = engine.evaluateToolCall('read_file', { path: '/etc/passwd' });
    expect(result.decision).toBe('block');
    expect(result.ruleId).toBe('1');
  });
  
  it('should block wildcard forbidden paths', () => {
    const result = engine.evaluateToolCall('fs_write', { filename: '/var/log/app.log' });
    expect(result.decision).toBe('block');
    expect(result.ruleId).toBe('1');
  });

  it('should block relative path etc/passwd without leading slash', () => {
    const result = engine.evaluateToolCall('read_file', { path: 'etc/passwd' });
    expect(result.decision).toBe('block');
  });

  it('should block uppercase /ETC/passwd path', () => {
    const result = engine.evaluateToolCall('read_file', { path: '/ETC/passwd' });
    expect(result.decision).toBe('block');
  });

  it('should block traversal paths like /tmp/../etc/passwd', () => {
    const result = engine.evaluateToolCall('read_file', { path: '/tmp/../etc/passwd' });
    expect(result.decision).toBe('block');
  });

  it('should block Windows backslash and drive-prefixed paths matching forbidden rules', () => {
    const res1 = engine.evaluateToolCall('read_file', { path: 'C:\\etc\\passwd' });
    expect(res1.decision).toBe('block');

    const res2 = engine.evaluateToolCall('read_file', { path: 'C:/var/log/system.log' });
    expect(res2.decision).toBe('block');
  });

  it('should allow legitimate paths that merely contain etc as substring', () => {
    const result = engine.evaluateToolCall('read_file', { path: '/home/dev/etc-configs/notes.txt' });
    expect(result.decision).toBe('allow');
  });

  it('should close file watcher on close()', () => {
    expect(() => engine.close()).not.toThrow();
  });

  it('should default to allow if no rules match', () => {
    const result = engine.evaluateToolCall('unknown_tool', { foo: 'bar' });
    expect(result.decision).toBe('allow');
  });
});
