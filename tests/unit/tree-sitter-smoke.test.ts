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

  it('SMOKE-05: Enforces exact AST node shapes for pipelines, substitutions, and redirects', () => {
    const parser = new Parser();
    try {
      delete (Bash as any).nodeSubclasses;
    } catch {}
    parser.setLanguage(Bash);

    // 1. Pipeline node shape invariant
    const pipeTree = parser.parse('cat logs.txt | grep error | wc -l');
    const pipeNode = pipeTree.rootNode.namedChildren[0];
    expect(pipeNode.type).toBe('pipeline');
    expect(pipeNode.namedChildren.length).toBe(3);
    pipeNode.namedChildren.forEach(child => {
      expect(child.type).toBe('command');
    });

    // 2. Command substitution node shape invariant ($() and ``)
    const subshellDollar = parser.parse('echo $(whoami)');
    const cmdDollar = subshellDollar.rootNode.namedChildren[0];
    const subshellNode = cmdDollar.namedChildren.find(n => n.type === 'command_substitution');
    expect(subshellNode).toBeDefined();
    expect(subshellNode?.type).toBe('command_substitution');

    // 3. Redirected statement node shape invariant
    const redirectTree = parser.parse('cat < input.txt > output.txt');
    const redirectNode = redirectTree.rootNode.namedChildren[0];
    expect(redirectNode.type).toBe('redirected_statement');
    const redirects = redirectNode.namedChildren.filter(n => n.type === 'file_redirect');
    expect(redirects.length).toBe(2);

    // 4. Parameter expansion node shape invariant
    const paramTree = parser.parse('echo ${SECRET_KEY:-default}');
    const cmdParam = paramTree.rootNode.namedChildren[0];
    const expansion = cmdParam.namedChildren.find(n => n.type === 'expansion');
    expect(expansion).toBeDefined();
  });
});

