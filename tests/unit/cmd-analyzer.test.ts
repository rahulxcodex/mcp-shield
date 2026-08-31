import { CmdAnalyzer } from '../../src/security/cmd-analyzer';
import { PowerShellASTAnalyzer } from '../../src/security/powershell-analyzer';

describe('CmdAnalyzer Unit Tests', () => {
  let analyzer: CmdAnalyzer;

  beforeEach(() => {
    const ps = new PowerShellASTAnalyzer();
    analyzer = new CmdAnalyzer(ps);
  });

  describe('Caret De-obfuscation', () => {
    it('de-obfuscates carets in command names (d^e^l)', () => {
      const res = analyzer.analyzeCommand('d^e^l /s /q C:\\');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('Destructive root deletion');
    });

    it('de-obfuscates carets in r^m^d^i^r', () => {
      const res = analyzer.analyzeCommand('r^m^d^i^r /s /q C:\\Windows');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('Destructive directory removal');
    });
  });

  describe('Compound Command Chaining', () => {
    it('blocks destructive command chained with &', () => {
      const res = analyzer.analyzeCommand('echo Safe & del /s /q C:\\');
      expect(res.isSafe).toBe(false);
    });

    it('blocks destructive command chained with &&', () => {
      const res = analyzer.analyzeCommand('dir && rmdir /s /q C:\\');
      expect(res.isSafe).toBe(false);
    });

    it('blocks destructive command chained with ||', () => {
      const res = analyzer.analyzeCommand('whoami || del /s /q %SYSTEMROOT%');
      expect(res.isSafe).toBe(false);
    });
  });

  describe('cmd.exe Switches and Wrappers', () => {
    it('unwraps cmd.exe /c and blocks inner destructive deletion', () => {
      const res = analyzer.analyzeCommand('cmd.exe /c "del /s /q C:\\"');
      expect(res.isSafe).toBe(false);
    });

    it('unwraps cmd.exe /s /c and blocks inner powershell execution', () => {
      const res = analyzer.analyzeCommand('cmd.exe /s /c "powershell -c Remove-Item -Recurse C:\\"');
      expect(res.isSafe).toBe(false);
    });

    it('blocks detached process creation via start cmd', () => {
      const res = analyzer.analyzeCommand('start cmd.exe /c del /s /q C:\\');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('start');
    });
  });

  describe('System Recovery and Volume Shadow Copies', () => {
    it('blocks vssadmin delete shadows', () => {
      const res = analyzer.analyzeCommand('vssadmin delete shadows /all /quiet');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('vssadmin delete shadows');
    });

    it('blocks bcdedit disabling recovery', () => {
      const res = analyzer.analyzeCommand('bcdedit /set {default} recoveryenabled No');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('bcdedit');
    });
  });

  describe('Environment and Delayed Expansion', () => {
    it('blocks delayed expansion variable execution !CMD!', () => {
      const res = analyzer.analyzeCommand('cmd.exe /v:on /c "!CMD!"');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('delayed expansion');
    });

    it('blocks sensitive environment variable access %AWS_SECRET_ACCESS_KEY%', () => {
      const res = analyzer.analyzeCommand('echo %AWS_SECRET_ACCESS_KEY%');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('%AWS_SECRET_ACCESS_KEY%');
    });
  });
});
