import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';

describe('Tree-sitter Parser Smoke & Multi-Realm Integrity Test Suite', () => {
  it('SMOKE-01: Correctly instantiates parser and sets Bash grammar', () => {
    const parser = new Parser();
    try {
      delete (Bash as any).nodeSubclasses;
    } catch {}
    parser.setLanguage(Bash);
    expect(parser.getLanguage()).toBeDefined();
  });

  it('SMOKE-02: Successfully parses basic command and retrieves rootNode', () => {
    const parser = new Parser();
    try {
      delete (Bash as any).nodeSubclasses;
    } catch {}
    parser.setLanguage(Bash);

    const tree = parser.parse('ls -la');
    expect(tree).toBeDefined();
    expect(tree.rootNode).toBeDefined();
    expect(tree.rootNode.type).toBe('program');
    expect(tree.rootNode.childCount).toBeGreaterThan(0);
    expect(tree.rootNode.startPosition).toEqual({ row: 0, column: 0 });
    expect(tree.rootNode.endPosition).toEqual({ row: 0, column: 6 });
  });

  it('SMOKE-03: Navigates AST child nodes and verifies node types for shell commands', () => {
    const parser = new Parser();
    try {
      delete (Bash as any).nodeSubclasses;
    } catch {}
    parser.setLanguage(Bash);

    const tree = parser.parse('rm -rf /');
    expect(tree.rootNode).toBeDefined();
    
    const commandNode = tree.rootNode.namedChildren[0];
    expect(commandNode).toBeDefined();
    expect(commandNode.type).toBe('command');
    
    const tokens = commandNode.namedChildren.map((n: Parser.SyntaxNode) => n.text);
    expect(tokens[0]).toBe('rm');
    expect(tokens).toContain('-rf');
    expect(tokens).toContain('/');
  });

  it('SMOKE-04: Repeated parsing under sustained 1,000-iteration load without parse state leaks', () => {
    const parser = new Parser();
    try {
      delete (Bash as any).nodeSubclasses;
    } catch {}
    parser.setLanguage(Bash);

    const commands = [
      'git status',
      'rm -rf /tmp/scratch',
      'find . -name "*.ts"',
      'cat /etc/passwd',
      'echo "hello world" | grep hello'
    ];

    for (let i = 0; i < 1000; i++) {
      const cmd = commands[i % commands.length];
      const tree = parser.parse(cmd);
      expect(tree.rootNode).toBeDefined();
      expect(tree.rootNode.type).toBe('program');
    }
  });
});
