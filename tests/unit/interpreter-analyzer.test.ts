import { UnifiedInterpreterClassifier } from '../../src/security/interpreter-analyzer';

describe('UnifiedInterpreterClassifier & Interpreter Analyzers (Roadmap Section 2)', () => {
  const classifier = new UnifiedInterpreterClassifier();

  it('classifies and analyzes standard bash commands through Bash analyzer', () => {
    const result = classifier.analyze('ls -la /workspace');
    expect(result.interpreter).toBe('bash');
    expect(result.isSafe).toBe(true);
  });

  it('detects dangerous bash commands (e.g. fork bombs)', () => {
    const result = classifier.analyze(':(t{ :|:&};:');
    expect(result.interpreter).toBe('bash');
    expect(result.isSafe).toBe(false);
  });

  it('classifies and routes PowerShell commands to PowerShell analyzer', () => {
    const safeResult = classifier.analyze('Get-Process | Select-Object -First 10');
    expect(safeResult.interpreter).toBe('powershell');
    expect(safeResult.isSafe).toBe(true);

    const dangerousResult = classifier.analyze('powershell -EncodedCommand JABhID0AIApGBIJwA=');
    expect(dangerousResult.interpreter).toBe('powershell');
    expect(dangerousResult.isSafe).toBe(false);
  });

  it('classifies and routes cmd commands to Cmd analyzer', () => {
    const safeResult = classifier.analyze('dir /s *.json');
    expect(safeResult.interpreter).toBe('cmd');
    expect(safeResult.isSafe).toBe(true);

    const dangerousResult = classifier.analyze('cmd.exe /c del /f /q %USERPROFILE%\\secrets.txt');
    expect(dangerousResult.interpreter).toBe('cmd');
    expect(dangerousResult.isSafe).toBe(false);
  });

  it('intercepts multi-interpreter execution chaining', () => {
    const chained = 'python3 -c "import os; os.system(\'bash\')"';
    const result = classifier.analyze(chained);
    expect(result.isSafe).toBe(false);
    expect(result.evidence.some(e => e.detectorId === 'multi-interpreter-analyzer')).toBe(true);
  });
});