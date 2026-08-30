import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';
import * as path from 'path';

export class ASTAnalyzer {
  private parser: Parser;

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Bash);
  }

  public analyzeCommand(command: string): { isSafe: boolean; reason?: string } {
    const tree = this.parser.parse(command);
    return this.walk(tree.rootNode);
  }

  private walk(node: Parser.SyntaxNode): { isSafe: boolean; reason?: string } {
    // 1. Check for subshells $( ) or ` `
    if (node.type === 'command_substitution' || node.type === 'process_substitution') {
      return { isSafe: false, reason: `Subshells and process substitutions are blocked: ${node.text}` };
    }

    // 2. Check for pipe-to-interpreter
    if (node.type === 'pipeline') {
      const commands = node.namedChildren;
      if (commands.length > 1) {
        const lastCmd = commands[commands.length - 1];
        
        if (lastCmd && lastCmd.type === 'subshell') {
           return { isSafe: false, reason: `Piping to subshell is blocked.` };
        }

        if (lastCmd && lastCmd.type === 'command') {
          const cmdNameNode = lastCmd.namedChildren.find((n: Parser.SyntaxNode) => n.type === 'command_name');
          if (cmdNameNode) {
            const interpreter = path.basename(cmdNameNode.text.trim());
            if (['sh', 'bash', 'zsh', 'python', 'node', 'ruby'].includes(interpreter)) {
              return { isSafe: false, reason: `Piping to interpreter '${interpreter}' is blocked.` };
            }
          }
        }
      }
    }

    // 3. Check for destructive rm (rm -rf /)
    if (node.type === 'command') {
      const cmdNameNode = node.namedChildren.find((n: Parser.SyntaxNode) => n.type === 'command_name');
      if (cmdNameNode && path.basename(cmdNameNode.text.trim()) === 'rm') {
        const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
        const hasRecursive = args.some((a: Parser.SyntaxNode) => a.text.includes('-r') || a.text.includes('-R') || a.text.includes('--recursive'));
        const hasDangerousTarget = args.some((a: Parser.SyntaxNode) => {
          const t = a.text;
          return t === '/' || t === '/*' || t === '~' || t === '.*' || t.startsWith('/etc') || t.startsWith('/var') || t.startsWith('/usr') || t.startsWith('/bin');
        });
        
        if (hasRecursive && hasDangerousTarget) {
          return { isSafe: false, reason: `Destructive root deletion blocked: ${node.text}` };
        }
      }
    }

    // Recurse down the tree
    for (const child of node.namedChildren) {
      const result = this.walk(child);
      if (!result.isSafe) return result;
    }

    return { isSafe: true };
  }
}
