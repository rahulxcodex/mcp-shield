import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { ConfigLoader } from '../../src/security/config';

describe('Config Safety, Tamper Protection & Path Resolution', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'config-safety-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
    delete process.env.MCP_SHIELD_CONFIG_PATH;
    delete process.env.MCP_SHIELD_CONFIG_SHA256;
  });

  it('CFG-01: Canonical resolution resolves custom path or env override', () => {
    const customConfig = path.join(tempDir, 'custom.yaml');
    fs.writeFileSync(customConfig, 'version: "1.0"\nprofile: default\nmode: audit\n', 'utf8');

    process.env.MCP_SHIELD_CONFIG_PATH = customConfig;
    const resolved = ConfigLoader.resolveConfigPath();
    expect(resolved).toBe(path.resolve(customConfig));
  });

  it('CFG-02: Enforces SHA-256 tamper verification when MCP_SHIELD_CONFIG_SHA256 is configured', () => {
    const yaml = require('js-yaml');
    const configPath = path.join(tempDir, 'shield.yaml');
    const validContent = yaml.dump(ConfigLoader.getHardenedProfile());
    fs.writeFileSync(configPath, validContent, 'utf8');

    const validHash = crypto.createHash('sha256').update(validContent).digest('hex');
    process.env.MCP_SHIELD_CONFIG_SHA256 = validHash;

    // Correct checksum succeeds
    expect(() => ConfigLoader.load(configPath)).not.toThrow();

    // Attacker tampers with config file before startup
    fs.writeFileSync(configPath, validContent + '\n# injected comment\n', 'utf8');

    // Mismatched checksum throws integrity error
    expect(() => ConfigLoader.load(configPath)).toThrow(/CONFIG INTEGRITY VIOLATION/);
  });

  it('CFG-03: Warns on unsafe high-priority catch-all allow rule', () => {
    const unsafeConfig: any = {
      version: '1.0',
      profile: 'test',
      mode: 'enforce',
      rules: [
        { id: 'catch-all', name: 'Catch All Allow', priority: 90, action: 'allow' },
        { id: 'block-rm', name: 'Block RM', priority: 50, targetTools: ['*rm*'], action: 'block' }
      ]
    };

    const safety = ConfigLoader.validatePolicySafety(unsafeConfig);
    expect(safety.isSafe).toBe(false);
    expect(safety.warnings[0]).toContain('Catch-all allow rule');
  });
});
