import * as fs from 'fs';
import * as path from 'path';
import { CapabilityInferencer, ToolProfile } from '../../src/security/capabilities';
import { ContainerSandbox } from '../../src/sandbox/container-sandbox';
import { COWFileSystem } from '../../src/sandbox/cow-fs';
import { SecretVault } from '../../src/security/vault';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { PolicyEngine } from '../../src/security/policy-engine';

describe('MCP-Shield Core Security Invariants', () => {
  const testWorkspace = path.join(process.cwd(), '.mcp-shield-invariant-test');

  beforeAll(() => {
    fs.mkdirSync(testWorkspace, { recursive: true });
  });

  afterAll(() => {
    try {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    } catch {}
  });

  describe('Invariant 1: Secret Restoration Trust Boundary', () => {
    test('UNTRUSTED servers/tools NEVER receive restored secrets', () => {
      const untrustedCaps = CapabilityInferencer.getDeclared({});
      const inferredCaps = CapabilityInferencer.infer('untrusted_tool', { properties: { token: { type: 'string' } } }, '');
      const trust = CapabilityInferencer.calculateTrustLevel(untrustedCaps, inferredCaps);
      
      expect(trust).toBe('UNTRUSTED');
      
      // Invariant assertion: In proxy.ts, isTrusted must be true and secretAccess must be true
      const canRestore = (trust === 'TRUSTED') && (inferredCaps.secretAccess || untrustedCaps.secretAccess);
      expect(canRestore).toBe(false);
    });

    test('SUSPICIOUS servers/tools (with undeclared capability) NEVER receive restored secrets', () => {
      // Declares only read, but schema accepts command & api_key
      const declared = { filesystemRead: true, filesystemWrite: false, shellExecution: false, networkAccess: false, processSpawn: false, destructiveOperation: false, secretAccess: false };
      const inferred = CapabilityInferencer.infer('suspicious_tool', { properties: { command: { type: 'string' }, api_key: { type: 'string' } } }, '');
      const trust = CapabilityInferencer.calculateTrustLevel(declared, inferred);
      
      expect(trust).toBe('SUSPICIOUS');
      const canRestore = (trust === 'TRUSTED') && (declared.secretAccess || inferred.secretAccess);
      expect(canRestore).toBe(false);
    });

    test('TRUSTED servers receive restored secrets ONLY when declared secretAccess capability is present', () => {
      const declaredWithSecret = { filesystemRead: true, filesystemWrite: false, shellExecution: false, networkAccess: false, processSpawn: false, destructiveOperation: false, secretAccess: true };
      const inferredWithSecret = { filesystemRead: true, filesystemWrite: false, shellExecution: false, networkAccess: false, processSpawn: false, destructiveOperation: false, secretAccess: true };
      const trust1 = CapabilityInferencer.calculateTrustLevel(declaredWithSecret, inferredWithSecret);
      expect(trust1).toBe('TRUSTED');
      expect(trust1 === 'TRUSTED' && declaredWithSecret.secretAccess).toBe(true);

      const declaredWithoutSecret = { filesystemRead: true, filesystemWrite: false, shellExecution: false, networkAccess: false, processSpawn: false, destructiveOperation: false, secretAccess: false };
      const inferredWithoutSecret = { filesystemRead: true, filesystemWrite: false, shellExecution: false, networkAccess: false, processSpawn: false, destructiveOperation: false, secretAccess: false };
      const trust2 = CapabilityInferencer.calculateTrustLevel(declaredWithoutSecret, inferredWithoutSecret);
      expect(trust2).toBe('TRUSTED');
      expect(trust2 === 'TRUSTED' && declaredWithoutSecret.secretAccess).toBe(false);
    });
  });

  describe('Invariant 2: Container Sandbox Security Invariants', () => {
    test('strictly rejects "network: host" without explicit unsafeOverrides', () => {
      expect(() => {
        new ContainerSandbox({ enabled: true, network: 'host' });
      }).toThrow(/INSECURE CONTAINER CONFIGURATION/);
    });

    test('permits "network: host" only when unsafeOverrides: true is explicitly configured', () => {
      expect(() => {
        new ContainerSandbox({ enabled: true, network: 'host', unsafeOverrides: true });
      }).not.toThrow();
    });

    test('always generates arguments enforcing --cap-drop=ALL and no-new-privileges', () => {
      const sandbox = new ContainerSandbox({ enabled: true });
      const args = sandbox.buildDockerArgs('node', ['index.js']);
      
      expect(args).toContain('--cap-drop=ALL');
      expect(args).toContain('--security-opt=no-new-privileges');
      expect(args).toContain('--read-only');
      expect(args).toContain('--network=none');
    });
  });

  describe('Invariant 3: Copy-on-Write Symlink Refusal & Identity Protection', () => {
    test('strictly refuses symlink targets during stageWrite', () => {
      const cow = new COWFileSystem();
      const realFile = path.join(testWorkspace, 'real_target.txt');
      const symlinkFile = path.join(testWorkspace, 'symlink_target.txt');
      
      fs.writeFileSync(realFile, 'real content', 'utf8');
      try {
        fs.symlinkSync(realFile, symlinkFile);
        
        expect(() => {
          cow.stageWrite(symlinkFile, 'malicious write attempt');
        }).toThrow(/COW SECURITY VIOLATION: Symlink target/);
      } catch (e: any) {
        if (e.code !== 'EPERM') throw e; // Handle Windows symlink privilege differences
      }
    });

    test('detects and blocks symlink replacement before commit (TOCTOU)', () => {
      const cow = new COWFileSystem();
      const targetFile = path.join(testWorkspace, 'toctou_file.txt');
      fs.writeFileSync(targetFile, 'initial content', 'utf8');

      const staged = cow.stageWrite(targetFile, 'updated staged content');

      // Simulate malicious attacker replacing file with a different inode
      fs.unlinkSync(targetFile);
      fs.writeFileSync(targetFile, 'replaced by attacker', 'utf8');

      expect(() => {
        cow.commit(staged.stagingPath, staged.absoluteOriginalPath, staged.originalIdentity);
      }).toThrow(/COW TOCTOU DETECTED: File identity changed/);
    });
  });

  describe('Invariant 4: Keyed HMAC Vault & UTF-8 Entropy Calculation', () => {
    test('SecretVault uses keyed HMAC indexing and decrypts cleanly', () => {
      const vault = new SecretVault();
      const secret = 'sk-ant-api03-abcdef1234567890abcdef1234567890';
      const token1 = vault.store(secret);
      const token2 = vault.store(secret);
      
      // Bijective mapping for identical secret
      expect(token1).toBe(token2);
      expect(vault.retrieve(token1)).toBe(secret);
      
      vault.clear();
      expect(vault.retrieve(token1)).toBeNull();
    });

    test('SecretSanitizer calculates entropy over UTF-8 bytes', () => {
      const sanitizer = new SecretSanitizer();
      const asciiEntropy = sanitizer.calculateEntropy('abcdefghijklmnopqrstuvwxyz0123456789');
      expect(asciiEntropy).toBeGreaterThan(4.5);

      const emptyEntropy = sanitizer.calculateEntropy('');
      expect(emptyEntropy).toBe(0);
    });
  });

  describe('Invariant 5: PolicyEngine Regex Metacharacter Escaping', () => {
    test('escapes special regex characters in targetTools and matches properly', () => {
      const engine = new PolicyEngine({
        version: '1.0',
        profile: 'developer',
        redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.5 },
        sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: true },
        egress: { enabled: true, allowMode: 'allow', allowPrivateNetworks: false, blockLoopback: true, blockLinkLocal: true, blockMetadataEndpoints: true },
        rules: [
          {
            id: 'block-special-tool',
            name: 'Block tool with regex special characters',
            priority: 100,
            targetTools: ['app.service[1]+tool*'],
            riskLevel: 'CRITICAL',
            action: 'block'
          }
        ],
        audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
      });

      // Matches literal 'app.service[1]+tool_exec'
      const matchResult = engine.evaluate({
        toolName: 'app.service[1]+tool_exec',
        args: {},
        evidence: []
      });
      expect(matchResult.decision).toBe('block');

      // Does not false-positive match 'appXservice111tool_exec' because . [ ] + are escaped
      const nonMatchResult = engine.evaluate({
        toolName: 'appXservice111tool_exec',
        args: {},
        evidence: []
      });
      expect(nonMatchResult.decision).toBe('block'); // Fallback default deny
      expect(nonMatchResult.reasonCode).toBe('DEFAULT_DENY_NO_CAPABILITY_MATCH');
    });
  });
});
