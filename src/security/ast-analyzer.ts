import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';
import * as path from 'path';

export interface ASTAnalysisResult {
  isSafe: boolean;
  reason?: string;
}

export class ASTAnalyzer {
  private parser: Parser;
  private readonly MAX_RECURSION_DEPTH = 50;

  private readonly SAFE_PIPE_TARGETS = new Set([
    'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'cat', 'head', 'tail',
    'less', 'more', 'jq', 'cut', 'tr', 'column', 'tee', 'nl', 'fold',
    'fmt', 'expand', 'unexpand', 'paste', 'tac', 'rev', 'diff', 'comm'
  ]);

  private readonly INTERPRETERS = new Set([
    'bash', 'sh', 'zsh', 'dash', 'ksh', 'csh', 'tcsh',
    'python', 'python2', 'python3', 'perl', 'ruby', 'php',
    'node', 'deno', 'bun', 'lua', 'powershell', 'pwsh', 'cmd', 'cmd.exe'
  ]);

  private readonly COMMAND_WRAPPERS = new Set([
    'sudo', 'doas', 'pkexec', 'env', 'command', 'builtin',
    'nohup', 'setsid', 'time', 'nice', 'stdbuf', 'timeout', 'chroot',
    'xargs', 'busybox', 'toybox', 'runuser', 'su'
  ]);

  private readonly DESTRUCTIVE_TOOLS = new Set([
    'shred', 'srm', 'wipe', 'del', 'rd', 'rmdir', 'erase'
  ]);

  private readonly DISK_FORMAT_TOOLS = new Set([
    'mkfs', 'fdisk', 'parted', 'gdisk', 'sfdisk', 'cfdisk', 'format'
  ]);

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Bash);
  }

  public analyzeCommand(command: string): ASTAnalysisResult {
    if (!command || !command.trim()) return { isSafe: true };

    // 1. Prevent synchronous tree-sitter parsing DoS on oversized commands
    if (command.length > 64 * 1024) {
      return { isSafe: false, reason: 'Command size exceeds 64KB safety limit (DoS prevention)' };
    }

    // 2. Fast regex pre-filter for common fork bomb patterns
    const normalized = command.replace(/\s+/g, '');
    if (
      normalized.includes(':(){:|:&};:') ||
      normalized.includes(':(){:|:&};') ||
      normalized.includes('bomb(){bomb|bomb&};bomb') ||
      normalized.includes('x(){x|x&};x') ||
      normalized.includes('fork(){fork|fork&};fork')
    ) {
      return { isSafe: false, reason: 'Fork bomb pattern detected' };
    }

    // 3. De-obfuscate $IFS, ${IFS}, and ANSI C quoted space substitutions
    const deIfsCommand = command
      .replace(/\$\{IFS(?::[^}]+)?\}|\$IFS(?:\$9|\$@|\$\*)?/g, ' ')
      .replace(/\$'[\t\n\s\\]+'|\$'\\x20'|\$'\\40'/gi, ' ');
    if (deIfsCommand !== command) {
      try {
        const deIfsTree = this.parser.parse(deIfsCommand);
        const deIfsResult = this.walk(deIfsTree.rootNode, 0);
        if (!deIfsResult.isSafe) {
          return { isSafe: false, reason: `$IFS evasion detected: ${deIfsResult.reason}` };
        }
      } catch {}
    }

    try {
      const tree = this.parser.parse(command);
      return this.walk(tree.rootNode, 0);
    } catch (err: any) {
      return { isSafe: false, reason: `AST Parsing Failure: ${err.message}` };
    }
  }

  private normalizeToken(raw: string): string {
    if (!raw) return '';
    let clean = raw
      .replace(/^['"]|['"]$/g, '')
      .replace(/\\/g, '')      // remove all backslash escapes e.g. \r\m\ -> rm
      .replace(/['"]/g, '')    // remove embedded quotes like r""m -> rm
      .trim();

    // Extract fallback / default from parameter expansions e.g. ${CMD:-rm} -> rm
    const paramMatch = /^\$\{[^}:-]+:?[-+=?]([^}]+)\}$/.exec(clean);
    if (paramMatch) {
      clean = paramMatch[1].replace(/^['"]|['"]$/g, '').trim();
    }

    return clean;
  }

  private isDangerousTarget(rawPath: string): boolean {
    const clean = this.normalizeToken(rawPath).replace(/\\/g, '/');
    if (!clean) return false;

    // Exact dangerous root/wildcard tokens
    if (
      ['/', '/*', '*', '~', '~/*', '.*', '.', '..', '$HOME', '$HOME/*', '%USERPROFILE%'].includes(clean) ||
      clean.startsWith('~')
    ) {
      return true;
    }

    // Multi-slash root like /// or ////*
    if (/^\/+[*]?$/.test(clean)) return true;

    // Path normalization check
    let normalized = clean;
    try {
      normalized = path.posix.normalize(clean);
    } catch {}

    if (
      normalized === '/' ||
      normalized === '.' ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      normalized.includes('/../')
    ) {
      return true;
    }

    // Unix system root directories
    const DANGEROUS_PREFIXES = [
      '/etc', '/var', '/usr', '/bin', '/sbin', '/lib', '/lib64',
      '/root', '/home', '/opt', '/srv', '/boot', '/sys', '/proc', '/dev'
    ];
    for (const prefix of DANGEROUS_PREFIXES) {
      if (normalized === prefix || normalized === `${prefix}/*` || normalized.startsWith(`${prefix}/`)) {
        return true;
      }
    }

    // Windows system root directories
    const DANGEROUS_WIN_PREFIXES = [
      'c:', 'c:/', 'c:/*', 'c:/windows', 'c:/windows/system32',
      'c:/program files', 'c:/users', '%systemroot%', '%windir%'
    ];
    const lowerNorm = normalized.toLowerCase();
    for (const winPrefix of DANGEROUS_WIN_PREFIXES) {
      if (lowerNorm === winPrefix || lowerNorm.startsWith(`${winPrefix}/`)) {
        return true;
      }
    }

    return false;
  }

  private unwrapCommandTokens(tokens: string[]): { cmdName: string; args: string[] } {
    let index = 0;
    while (index < tokens.length) {
      const raw = tokens[index];
      const normalized = this.normalizeToken(raw);
      const base = path.basename(normalized.toLowerCase());

      // If env var assignment before command (e.g. FOO=bar)
      if (normalized.includes('=') && !normalized.startsWith('-')) {
        index++;
        continue;
      }

      if (this.COMMAND_WRAPPERS.has(base)) {
        index++;
        // Handle specific wrapper arguments
        if (base === 'sudo' || base === 'doas' || base === 'pkexec') {
          while (index < tokens.length) {
            const opt = this.normalizeToken(tokens[index]);
            if (opt.startsWith('-')) {
              index++;
              if (['-u', '-g', '-C', '-h', '-p'].includes(opt) && index < tokens.length) {
                index++;
              }
            } else {
              break;
            }
          }
        } else if (base === 'timeout') {
          while (index < tokens.length) {
            const opt = this.normalizeToken(tokens[index]);
            if (opt.startsWith('-')) {
              index++;
              if (['-s', '-k', '--signal', '--kill-after'].includes(opt) && index < tokens.length) {
                index++;
              }
            } else {
              // Skip the duration token (e.g. 10s, 30, 1m)
              index++;
              break;
            }
          }
        } else if (base === 'nice') {
          while (index < tokens.length) {
            const opt = this.normalizeToken(tokens[index]);
            if (opt === '-n' && index + 1 < tokens.length) {
              index += 2;
            } else if (opt.startsWith('-')) {
              index++;
            } else {
              break;
            }
          }
        } else if (base === 'stdbuf') {
          while (index < tokens.length) {
            const opt = this.normalizeToken(tokens[index]);
            if (opt.startsWith('-i') || opt.startsWith('-o') || opt.startsWith('-e')) {
              index++;
            } else if (opt.startsWith('-')) {
              index++;
            } else {
              break;
            }
          }
        } else if (base === 'env') {
          while (index < tokens.length) {
            const opt = this.normalizeToken(tokens[index]);
            if (opt.startsWith('-')) {
              index++;
              if (opt === '-u' && index < tokens.length) {
                index++;
              }
            } else if (opt.includes('=')) {
              index++;
            } else {
              break;
            }
          }
        }
        continue;
      }

      return {
        cmdName: base,
        args: tokens.slice(index + 1).map(t => this.normalizeToken(t))
      };
    }

    return { cmdName: '', args: [] };
  }

  private walk(node: Parser.SyntaxNode | null | undefined, depth: number): ASTAnalysisResult {
    if (!node || typeof node.type !== 'string') {
      return { isSafe: true };
    }

    if (depth > this.MAX_RECURSION_DEPTH) {
      return { isSafe: false, reason: 'Command AST recursion depth exceeded maximum limit' };
    }

    // 1. Check for subshells and process substitutions
    if (node.type === 'command_substitution' || node.type === 'process_substitution') {
      return { isSafe: false, reason: `Subshells and process substitutions are blocked: "${node.text}"` };
    }

    // 2. Check for redirected statements (e.g. bash <<< "...", bash < evil.sh, heredocs)
    if (node.type === 'redirected_statement') {
      const children = Array.isArray(node.namedChildren) ? node.namedChildren : [];
      const hasRedirect = children.some(c =>
        c && (c.type === 'herestring_redirect' || c.type === 'heredoc_redirect' || c.type === 'file_redirect')
      );
      if (hasRedirect) {
        const cmdChild = children.find(n => n && n.type === 'command') || 
          (typeof (node as any).childForFieldName === 'function' ? (node as any).childForFieldName('body') : null);
        if (cmdChild && Array.isArray(cmdChild.namedChildren)) {
          const tokenNodes = cmdChild.namedChildren.filter((n: Parser.SyntaxNode) =>
            n && n.type && n.type !== 'comment' && !n.type.includes('redirect')
          );
          const { cmdName } = this.unwrapCommandTokens(tokenNodes.map((n: Parser.SyntaxNode) => n.text));
          if (this.INTERPRETERS.has(cmdName)) {
            return { isSafe: false, reason: `Interpreter script feeding via redirection is blocked: "${node.text}"` };
          }
        }
      }
    }

    // 3. Check for raw disk output redirections (e.g. > /dev/sda)
    if (node.type === 'file_redirect') {
      const children = Array.isArray(node.namedChildren) ? node.namedChildren : [];
      const dest = children.find(n => n && (n.type === 'word' || n.type === 'string'));
      if (dest && dest.text) {
        const normalizedDest = this.normalizeToken(dest.text);
        if (/^\/dev\/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|loop\d|mem|kmem)/i.test(normalizedDest)) {
          return { isSafe: false, reason: `Direct raw disk device write redirection blocked: "${node.text}"` };
        }
      }
    }

    // 4. Command node validation
    if (node.type === 'command') {
      const children = Array.isArray(node.namedChildren) ? node.namedChildren : [];
      const tokenNodes = children.filter(n =>
        n && n.type && n.type !== 'comment' && !n.type.includes('redirect')
      );

      const tokens = tokenNodes.map(n => n.text);
      const { cmdName, args } = this.unwrapCommandTokens(tokens);

      if (cmdName) {
        // Dynamic execution primitives
        if (cmdName === 'eval' || cmdName === 'exec') {
          return { isSafe: false, reason: `Dynamic evaluation primitive "${cmdName}" is blocked: "${node.text}"` };
        }

        // Dangerous alias definitions
        if (cmdName === 'alias') {
          const hasDangerousAlias = args.some(t => {
            const val = t.split('=')[1] || '';
            const cleanVal = val.replace(/^['"]|['"]$/g, '');
            return this.analyzeCommand(cleanVal).isSafe === false;
          });
          if (hasDangerousAlias) {
            return { isSafe: false, reason: `Dangerous alias definition blocked: "${node.text}"` };
          }
        }

        // Destructive rm / del / erase check
        if (cmdName === 'rm' || cmdName === 'del' || cmdName === 'erase') {
          const hasRecursive = cmdName === 'del' || cmdName === 'erase' || args.some(t => {
            if (t === '--recursive') return true;
            if (t.startsWith('-') && !t.startsWith('--')) {
              return t.includes('r') || t.includes('R') || t.includes('s') || t.includes('S');
            }
            if (t.startsWith('/')) { // Windows /s /q
              return t.toLowerCase() === '/s';
            }
            return false;
          });
          const hasDangerousTarget = args.some(t => this.isDangerousTarget(t));
          if (hasRecursive && hasDangerousTarget) {
            return { isSafe: false, reason: `Destructive root deletion blocked: "${node.text}"` };
          }
        }

        // Safe pipe tool subshell escape check (awk/sed arbitrary command execution)
        if (cmdName === 'awk' || cmdName === 'sed') {
          const hasSubshellEscape = args.some(a => 
            /system\s*\(|getline\s+[^<]+<|e\s+["']|\/bin\/(ba)?sh/i.test(a)
          );
          if (hasSubshellEscape) {
            return { isSafe: false, reason: `Subshell escape pattern detected in "${cmdName}": "${node.text}"` };
          }
        }

        // File shredding and wiping tools
        if (this.DESTRUCTIVE_TOOLS.has(cmdName)) {
          const hasDangerousTarget = args.some(t => this.isDangerousTarget(t));
          if (hasDangerousTarget || args.includes('-u') || args.includes('-z')) {
            return { isSafe: false, reason: `Destructive file wiping tool "${cmdName}" blocked: "${node.text}"` };
          }
        }

        // Recursive chmod / chown on root or system directories
        if (cmdName === 'chmod' || cmdName === 'chown') {
          const isRecursive = args.some(t => t === '-R' || t === '--recursive' || t.startsWith('-R'));
          const hasDangerousTarget = args.some(t => this.isDangerousTarget(t));
          if (isRecursive && hasDangerousTarget) {
            return { isSafe: false, reason: `Recursive system permission/ownership mutation with "${cmdName}" blocked: "${node.text}"` };
          }
        }

        // Dangerous system mv
        if (cmdName === 'mv') {
          const hasDangerousSource = args.some((t, i) => i < args.length - 1 && this.isDangerousTarget(t));
          const toNull = args.some(t => t === '/dev/null');
          if (hasDangerousSource || (toNull && args.some(t => this.isDangerousTarget(t)))) {
            return { isSafe: false, reason: `Destructive system move command "${cmdName}" blocked: "${node.text}"` };
          }
        }

        // Disk formatting and partitioning tools
        if (this.DISK_FORMAT_TOOLS.has(cmdName) || cmdName.startsWith('mkfs.')) {
          return { isSafe: false, reason: `Filesystem format command blocked: "${node.text}"` };
        }

        // Raw disk dd writes
        if (cmdName === 'dd') {
          if (args.some(a => /of=\/dev\/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|loop\d|mem|kmem)/i.test(a))) {
            return { isSafe: false, reason: `Raw disk write (dd) blocked: "${node.text}"` };
          }
        }

        // Dangerous find flags (-exec, -delete, -ok)
        if (cmdName === 'find') {
          if (args.some(a => a === '-exec' || a === '-execdir' || a === '-delete' || a === '-ok')) {
            return { isSafe: false, reason: `Dangerous find command with -exec or -delete blocked: "${node.text}"` };
          }
        }

        // Sourcing / executing scripts via source or .
        if (cmdName === 'source' || cmdName === '.') {
          const hasSuspiciousScript = args.some(t =>
            t.startsWith('/tmp/') || t.startsWith('/var/tmp/') || t.startsWith('/dev/shm/') || t.endsWith('.sh')
          );
          if (hasSuspiciousScript) {
            return { isSafe: false, reason: `Sourcing arbitrary shell script blocked: "${node.text}"` };
          }
        }

        // Direct interpreter inline/script execution or redirection feeding
        if (this.INTERPRETERS.has(cmdName)) {
          const hasInlineExec = args.some(text =>
            text === '-c' || text === '-e' || text === '-r' ||
            text.startsWith('/tmp/') || text.startsWith('/var/tmp/') || text.startsWith('/dev/shm/')
          );
          const hasRedirect = children.some(n =>
            n && (n.type === 'herestring_redirect' || n.type === 'heredoc_redirect' || n.type === 'file_redirect')
          );
          const isParentRedirected = node.parent?.type === 'redirected_statement';
          if (hasInlineExec || hasRedirect || isParentRedirected) {
            return { isSafe: false, reason: `Direct interpreter inline/script execution blocked: "${node.text}"` };
          }
        }
      }
    }

    // 5. Pipeline validation
    if (node.type === 'pipeline') {
      const commands = Array.isArray(node.namedChildren) ? node.namedChildren : [];
      for (let i = 1; i < commands.length; i++) {
        const pipedCmd = commands[i];
        if (!pipedCmd) continue;
        if (pipedCmd.type === 'command') {
          const children = Array.isArray(pipedCmd.namedChildren) ? pipedCmd.namedChildren : [];
          const tokenNodes = children.filter(n =>
            n && (n.type === 'command_name' || n.type === 'word' || n.type === 'string')
          );
          const tokens = tokenNodes.map(n => n.text);
          const { cmdName } = this.unwrapCommandTokens(tokens);

          if (cmdName) {
            if (!this.SAFE_PIPE_TARGETS.has(cmdName)) {
              return { isSafe: false, reason: `Piping to non-allowlisted command "${cmdName}" is blocked.` };
            }
          }
        } else {
          return { isSafe: false, reason: `Piping to compound statement or subshell is blocked.` };
        }
      }
    }

    // Recurse down the tree
    if (Array.isArray(node.namedChildren)) {
      for (const child of node.namedChildren) {
        if (child && typeof child.type === 'string') {
          const result = this.walk(child, depth + 1);
          if (!result.isSafe) return result;
        }
      }
    }

    return { isSafe: true };
  }
}

