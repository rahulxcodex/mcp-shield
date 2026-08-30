import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';
import * as path from 'path';

export class ASTAnalyzer {
  private parser: Parser;
  private readonly SAFE_PIPE_TARGETS = new Set([
    'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'cat', 'head', 'tail', 'less', 'more', 'jq', 'cut', 'tr'
  ]);

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Bash);
  }

  public analyzeCommand(command: string): { isSafe: boolean; reason?: string } {
    if (!command || !command.trim()) return { isSafe: true };
    // Prevent synchronous tree-sitter parsing DoS on oversized commands
    if (command.length > 64 * 1024) {
      return { isSafe: false, reason: 'Command size exceeds 64KB safety limit (DoS prevention)' };
    }

    // Check for fork bomb patterns
    if (command.includes(':(){ :|:& };:') || command.includes(':(){:|:&};:')) {
      return { isSafe: false, reason: 'Fork bomb pattern detected' };
    }

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
        const rawCmdText = cmdNameNode.text.trim();
        const normalizedCmd = rawCmdText.replace(/^['"]|['"]$/g, '').replace(/\\/g, '');
        const cmdName = path.basename(normalizedCmd.toLowerCase());

        // Block dynamic execution primitives
        if (cmdName === 'eval' || cmdName === 'exec') {
          return { isSafe: false, reason: `Dynamic evaluation primitive "${cmdName}" is blocked: "${node.text}"` };
        }

        const isDangerousTarget = (t: string) => {
          const clean = t.replace(/^['"]|['"]$/g, '');
          return (
            clean === '/' ||
            clean === '/*' ||
            clean === '*' ||
            clean === '~' ||
            clean === '.*' ||
            clean === '.' ||
            clean === '..' ||
            clean === '$HOME' ||
            clean.startsWith('/etc') ||
            clean.startsWith('/var') ||
            clean.startsWith('/usr') ||
            clean.startsWith('/bin') ||
            clean.startsWith('/home') ||
            clean.startsWith('/root') ||
            clean.startsWith('/opt') ||
            clean.startsWith('/srv') ||
            clean.startsWith('../../')
          );
        };

        if (cmdName === 'rm') {
          const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
          const hasRecursive = args.some((a: Parser.SyntaxNode) => {
            const t = a.text.replace(/^['"]|['"]$/g, '');
            return t === '-r' || t === '-R' || t === '-rf' || t === '-fr' || t.startsWith('-r') || t.startsWith('-R') || t === '--recursive';
          });
          const hasDangerousTarget = args.some((a: Parser.SyntaxNode) => isDangerousTarget(a.text));
          
          if (hasRecursive && hasDangerousTarget) {
            return { isSafe: false, reason: `Destructive root deletion blocked: "${node.text}"` };
          }
        }

        // Check for direct disk formatting or raw disk writing
        if (cmdName === 'mkfs' || cmdName.startsWith('mkfs') || cmdName === 'fdisk') {
          return { isSafe: false, reason: `Filesystem format command blocked: "${node.text}"` };
        }

        if (cmdName === 'dd') {
          const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
          if (args.some((a: Parser.SyntaxNode) => a.text.includes('of=/dev/'))) {
            return { isSafe: false, reason: `Raw disk write (dd) blocked: "${node.text}"` };
          }
        }

        // Check find with dangerous flags (-exec, -delete)
        if (cmdName === 'find') {
          const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
          if (args.some((a: Parser.SyntaxNode) => a.text.includes('-exec') || a.text.includes('-delete'))) {
            return { isSafe: false, reason: `Dangerous find command with -exec or -delete blocked: "${node.text}"` };
          }
        }

        // Direct execution of scripts or inline code via shell/interpreters (e.g. bash /tmp/x.sh, python3 -c "...")
        if (['bash', 'sh', 'zsh', 'python', 'python3', 'perl', 'ruby', 'php', 'node'].includes(cmdName)) {
          const args = node.namedChildren.filter((n: Parser.SyntaxNode) => n.type === 'word' || n.type === 'string');
          const hasInlineExec = args.some((a: Parser.SyntaxNode) => {
            const text = a.text.replace(/^['"]|['"]$/g, '');
            return text === '-c' || text === '-e' || text.startsWith('/tmp/') || text.startsWith('/var/tmp/') || text.startsWith('/dev/shm/') || text.endsWith('.sh');
          });
          if (hasInlineExec) {
            return { isSafe: false, reason: `Direct interpreter inline/script execution blocked: "${node.text}"` };
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
            const rawText = nameNode.text.trim().replace(/^['"]|['"]$/g, '');
            const name = path.basename(rawText.toLowerCase());
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
