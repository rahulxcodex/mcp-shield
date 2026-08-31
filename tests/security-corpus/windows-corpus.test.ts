import * as fs from 'fs';
import * as path from 'path';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { PowerShellASTAnalyzer } from '../../src/security/powershell-analyzer';
import { CmdAnalyzer } from '../../src/security/cmd-analyzer';

describe('Windows Adversarial Security Corpus Regression Harness', () => {
  let astAnalyzer: ASTAnalyzer;
  let psAnalyzer: PowerShellASTAnalyzer;
  let cmdAnalyzer: CmdAnalyzer;

  const loadCorpus = (fileName: string) => {
    const fullPath = path.join(__dirname, 'windows', fileName);
    return JSON.parse(fs.readFileSync(fullPath, 'utf8')) as Array<{
      category: string;
      description: string;
      payloads: string[];
    }>;
  };

  beforeAll(() => {
    astAnalyzer = new ASTAnalyzer();
    psAnalyzer = new PowerShellASTAnalyzer();
    cmdAnalyzer = new CmdAnalyzer(psAnalyzer);
  });

  describe('1. PowerShell Bypass Corpus (powershell-bypass.json)', () => {
    const corpus = loadCorpus('powershell-bypass.json');

    it('validates that all categories in powershell-bypass.json are covered', () => {
      expect(corpus.length).toBeGreaterThan(0);
      for (const section of corpus) {
        expect(section.payloads.length).toBeGreaterThan(0);
      }
    });

    it('blocks all PowerShell cmdlet alias evasions (del, rm, ri, rd, irm, iwr, saps, etc.)', () => {
      const section = corpus.find(c => c.category === 'powershell_cmdlet_aliases');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks all PowerShell parameter alias evasions (-r, -rec, -Confirm:$false, etc.)', () => {
      const section = corpus.find(c => c.category === 'powershell_parameter_aliases');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks all PowerShell dynamic invocations (&, $(...), scriptblocks, iex)', () => {
      const section = corpus.find(c => c.category === 'powershell_dynamic_invocation');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks all PowerShell .ps1 execution, dot-sourcing, and .NET reflection abuse', () => {
      const section = corpus.find(c => c.category === 'powershell_script_execution_and_reflection');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks sensitive credential access and environment variable dumps', () => {
      const section = corpus.find(c => c.category === 'powershell_sensitive_access');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });
  });

  describe('2. cmd.exe Bypass Corpus (cmd-bypass.json)', () => {
    const corpus = loadCorpus('cmd-bypass.json');

    it('blocks all caret escape sequence obfuscation (d^e^l, r^m^d^i^r, etc.)', () => {
      const section = corpus.find(c => c.category === 'cmd_caret_obfuscation');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks all compound chained cmd operations (&, &&, ||, pipes)', () => {
      const section = corpus.find(c => c.category === 'cmd_compound_chaining');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks cmd.exe wrapper evasions (/c, /s, /k, /q, start)', () => {
      const section = corpus.find(c => c.category === 'cmd_wrappers_and_spawns');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks cmd.exe system tampering (vssadmin, bcdedit, format, diskpart)', () => {
      const section = corpus.find(c => c.category === 'cmd_system_tampering');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });
  });

  describe('3. PowerShell Encoded Command Corpus (powershell-encoding.json)', () => {
    const corpus = loadCorpus('powershell-encoding.json');

    it('decodes and blocks all Base64 UTF-16LE / UTF-8 PowerShell payloads', () => {
      const section = corpus.find(c => c.category === 'powershell_encoded_commands');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
        expect(res.reason).toBeDefined();
      }
    });
  });

  describe('4. Windows Paths & Traversals Corpus (windows-paths.json)', () => {
    const corpus = loadCorpus('windows-paths.json');

    it('identifies and blocks dangerous target path traversals in commands', () => {
      const traversalSection = corpus.find(c => c.category === 'windows_path_traversal');
      expect(traversalSection).toBeDefined();

      for (const targetPath of traversalSection!.payloads) {
        const cmd = `del /s /q "${targetPath}"`;
        const res = astAnalyzer.analyzeCommand(cmd);
        expect(res.isSafe).toBe(false);
      }
    });

    it('identifies and blocks dangerous UNC and device paths in commands', () => {
      const uncSection = corpus.find(c => c.category === 'windows_unc_and_device_paths');
      expect(uncSection).toBeDefined();

      for (const targetPath of uncSection!.payloads) {
        const cmd = `Remove-Item -Recurse "${targetPath}"`;
        const res = astAnalyzer.analyzeCommand(cmd);
        expect(res.isSafe).toBe(false);
      }
    });
  });

  describe('5. Windows Environment Expansion Corpus (windows-env-expansion.json)', () => {
    const corpus = loadCorpus('windows-env-expansion.json');

    it('blocks sensitive credential access via %VAR% and $env:VAR and !VAR!', () => {
      const section = corpus.find(c => c.category === 'windows_sensitive_env_leak');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks destructive deletions targeting system directory environment variables', () => {
      const section = corpus.find(c => c.category === 'windows_env_destructive_targets');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });

    it('blocks environment enumeration attacks and delayed expansion execution', () => {
      const section = corpus.find(c => c.category === 'windows_env_enumeration');
      expect(section).toBeDefined();

      for (const payload of section!.payloads) {
        const res = astAnalyzer.analyzeCommand(payload);
        expect(res.isSafe).toBe(false);
      }
    });
  });

  describe('Benign Windows Commands Verification', () => {
    it('allows benign PowerShell inspection commands', () => {
      expect(astAnalyzer.analyzeCommand('Get-Process').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Get-Service -Name wuauserv').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Get-ChildItem -Path ./src -Recurse').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Get-Content ./package.json').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Write-Output "Build Completed"').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Get-Process | Select-Object -First 10').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('Get-ChildItem ./src | Where-Object { $_.Length -gt 0 }').isSafe).toBe(true);
    });

    it('allows benign cmd.exe commands', () => {
      expect(astAnalyzer.analyzeCommand('dir').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('dir /s *.ts').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('echo Hello World').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('type README.md').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('type package.json | findstr "version"').isSafe).toBe(true);
      expect(astAnalyzer.analyzeCommand('del .\\build-temp.tmp').isSafe).toBe(true);
    });
  });
});
