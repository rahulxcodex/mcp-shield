import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';
import * as path from 'path';

export class ASTAnalyzer {
  private parser: Parser;
  private readonly SAFE_PIPE_TARGETS = new Set([
    'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'cat', 'head', 'tail', 'less', 'more', 'jq', 'xargs', 'find', 'cut', 'tr'
  ]);

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Bash);
  }

  public analyzeCommand(command: string): { isSafe: boolean; reason?: string } {
    if (!command || !command.trim()) return { isSafe: true };
    try {
      const tree = this.parser.parse(command);
      return this.walk(tree.rootNode);
    } catch (err: any) {
      return { isSafe: false, reason: `AST Parsing Failure: ${err.message}` };
    }
  }

  private walk(node: Parser.SyntaxNode): { isSafe: boolean; reason?: string } {
    // 1. Check for subshells $( ) or ` `
    if (node.type === 'command_substitution' || node.type === 'process_substitution') {
      return { isSafe: false, reason: `Subshells and process substitutions are blocked: "${node.text}"` };
    }

    // 2. Check all command nodes (handles command lists, semicolons, &&, ||)
    if (node.type === 'command') {
      const cmdNameNode = node.namedChildren.find((n: Parser.SyntaxNode) => n.type === 'command_name');
      if (cmdNameNode) {
        const cmdName = path.basename(cmdNameNode.text.trim().toLowerCase());
        if (cmdName === 'rm') {
          const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
          const hasRecursive = args.some((a: Parser.SyntaxNode) => a.text.includes('-r') || a.text.includes('-R') || a.text.includes('--recursive'));
          const hasDangerousTarget = args.some((a: Parser.SyntaxNode) => {
            const t = a.text.replace(/["']/g, '');
            return t === '/' || t === '/*' || t === '~' || t === '.*' || t.startsWith('/etc') || t.startsWith('/var') || t.startsWith('/usr') || t.startsWith('/bin');
          });
          
          if (hasRecursive && hasDangerousTarget) {
            return { isSafe: false, reason: `Destructive root deletion blocked: "${node.text}"` };
          }
        }
      }
    }

    // 3. Check for pipe-to-interpreter
    if (node.type === 'pipeline') {
      const commands = node.namedChildren;
      for (let i = 1; i < commands.length; i++) {
        const pipedCmd = commands[i];
        if (pipedCmd.type === 'command') {
          const nameNode = pipedCmd.namedChildren.find((n: Parser.SyntaxNode) => n.type === 'command_name');
          if (nameNode) {
            const name = path.basename(nameNode.text.trim().toLowerCase());
            if (!this.SAFE_PIPE_TARGETS.has(name)) {
              return { isSafe: false, reason: `Piping to non-allowlisted command "${name}" is blocked.` };
            }
          }
        } else {
          return { isSafe: false, reason: `Piping to compound statement or subshell is blocked.` };
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
