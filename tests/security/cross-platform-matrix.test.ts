import { PathSecurityResolver } from '../../src/security/path-resolver';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { PowerShellASTAnalyzer } from '../../src/security/powershell-analyzer';
import { CmdAnalyzer } from '../../src/security/cmd-analyzer';
import { IpClassifier, EgressSecurityConfig } from '../../src/security/ip-utils';

describe('Roadmap Step 2 — Cross-Platform Security Matrix (Linux / Windows / macOS)', () => {
  const platforms = ['linux', 'win32', 'darwin'] as const;

  describe('1. Path Handling Invariants across OS Semantics', () => {
    it('enforces traversal detection across Windows backslashes, forward slashes, and mixed separators', () => {
      const traversalPaths = [
        '..\\..\\..\\Windows\\System32\\calc.exe',
        '../../../etc/passwd',
        'dir/..\\..\\..\\secret.key',
        'C:\\Users\\..\\..\\Windows\\System32\\cmd.exe'
      ];

      for (const p of traversalPaths) {
        const res = PathSecurityResolver.resolveForPolicy(p);
        expect(res.hasTraversalAttempt).toBe(true);
      }

      // UNC path recognition
      const uncRes = PathSecurityResolver.resolveForPolicy('\\\\attacker-server\\share\\evil.exe');
      expect(uncRes.isUnc).toBe(true);
    });

    it('consistently verifies containment inside allowed workspace for all path styles', () => {
      expect(PathSecurityResolver.isWithin('/workspace/project/file.txt', '/workspace')).toBe(true);
      expect(PathSecurityResolver.isWithin('/etc/passwd', '/workspace')).toBe(false);
      expect(PathSecurityResolver.isWithin('C:\\workspace\\project\\file.txt', 'C:\\workspace')).toBe(true);
      expect(PathSecurityResolver.isWithin('C:\\Windows\\System32\\drivers', 'C:\\workspace')).toBe(false);
    });
  });

  describe('2. Multi-Interpreter Command Execution Matrix', () => {
    let bashAnalyzer: ASTAnalyzer;
    let psAnalyzer: PowerShellASTAnalyzer;
    let cmdAnalyzer: CmdAnalyzer;

    beforeAll(() => {
      bashAnalyzer = new ASTAnalyzer();
      psAnalyzer = new PowerShellASTAnalyzer();
      cmdAnalyzer = new CmdAnalyzer(psAnalyzer);
    });

    it('Linux/POSIX Interpreter: Blocks destructive and subshell injection', () => {
      expect(bashAnalyzer.analyzeCommand('rm -rf /').isSafe).toBe(false);
      expect(bashAnalyzer.analyzeCommand('echo $(cat /etc/shadow)').isSafe).toBe(false);
      expect(bashAnalyzer.analyzeCommand('ls -la /tmp').isSafe).toBe(true);
    });

    it('Windows PowerShell Interpreter: Blocks IEX, encoded commands, and credential harvesting', () => {
      expect(psAnalyzer.analyzeCommand('Invoke-Expression "Get-Process"').isSafe).toBe(false);
      expect(psAnalyzer.analyzeCommand('powershell.exe -enc:SUVYKCJybSAtcmYgLyIp').isSafe).toBe(false);
      expect(psAnalyzer.analyzeCommand('Get-ChildItem -Path .').isSafe).toBe(true);
    });

    it('Windows CMD.exe Interpreter: Deobfuscates carets, percent vars, and blocks dangerous utilities', () => {
      expect(cmdAnalyzer.analyzeCommand('d^e^l /f /q C:\\Windows\\*').isSafe).toBe(false);
      expect(cmdAnalyzer.analyzeCommand('cmd.exe /c "vssadmin delete shadows"').isSafe).toBe(false);
      expect(cmdAnalyzer.analyzeCommand('type %AWS_SECRET_ACCESS_KEY%').isSafe).toBe(false);
      expect(cmdAnalyzer.analyzeCommand('dir').isSafe).toBe(true);
      expect(cmdAnalyzer.analyzeCommand('cmd.exe /c "dir C:\\"').isSafe).toBe(true);
    });
  });

  describe('3. Network Stack & Localhost Representation Matrix', () => {
    const strictEgress: EgressSecurityConfig = {
      enabled: true,
      allowMode: 'deny',
      allowedDomains: [],
      blockedDomains: [],
      allowPrivateNetworks: false,
      blockLoopback: true,
      blockLinkLocal: true,
      blockMetadataEndpoints: true
    };

    it('blocks loopback and metadata addresses across POSIX and Windows IP conventions', () => {
      const blockedDestinations = [
        '127.0.0.1',
        '127.0.1.1',
        '0x7f000001',           // Hex representation
        '2130706433',           // Dword integer representation
        '[::1]',                // IPv6 loopback
        '::ffff:127.0.0.1',     // IPv4 mapped inside IPv6
        '169.254.169.254',      // AWS/GCP/Azure link-local metadata
        'metadata.google.internal'
      ];

      for (const dest of blockedDestinations) {
        const check = IpClassifier.checkEgressViolation(dest, strictEgress);
        expect(check.isBlocked).toBe(true);
      }
    });
  });
});
