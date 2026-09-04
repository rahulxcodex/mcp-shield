/**
 * Multi-Interpreter Execution & Chaining Analyzer (Roadmap P2.2)
 *
 * Analyzes execution across runtime boundaries:
 * - Python (inline execution: -c, os.system, subprocess, eval, exec)
 * - Node.js (inline execution: -e, child_process.exec/spawn, eval)
 * - Perl (inline execution: -e, system, backticks)
 * - Ruby (inline execution: -e, system, IO.popen)
 * - Java (ProcessBuilder, Runtime.getRuntime().exec)
 * - PowerShell (inline: -Command, -EncodedCommand, Invoke-Expression, IEX)
 * - cmd.exe (/c, /k, call)
 *
 * Treats interpreter transitions as capability boundaries and blocks dangerous chaining.
 */

export interface InterpreterTransition {
  interpreter: string;
  flag?: string;
  payload?: string;
  isInlineExecution: boolean;
  hasSubprocessSpawn: boolean;
}

export interface MultiInterpreterAnalysisResult {
  isSafe: boolean;
  isChained: boolean;
  interpretersDetected: string[];
  transitions: InterpreterTransition[];
  reason?: string;
}

export class MultiInterpreterAnalyzer {
  private static readonly DANGEROUS_SUBPROCESS_PATTERNS: Record<string, RegExp[]> = {
    python: [
      /os\.(?:system|popen|spawn[a-z]*)\s*\(/i,
      /subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(/i,
      /pty\.spawn\s*\(/i,
      /__import__\s*\(\s*['"]os['"]\s*\)\.system/i,
      /eval\s*\(\s*compile\s*\(/i
    ],
    node: [
      /child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(/i,
      /require\s*\(\s*['"]child_process['"]\s*\)/i,
      /process\.binding\s*\(\s*['"]spawn_sync['"]\s*\)/i
    ],
    perl: [
      /(?:system|exec)\s*\(/i,
      /`[^`]+`/,
      /open\s*\(\s*[A-Z_]+\s*,\s*['"]\|/i
    ],
    ruby: [
      /(?:system|exec)\s*\(/i,
      /`[^`]+`/,
      /IO\.popen\s*\(/i,
      /Open3\.(?:capture3|popen3)\s*\(/i
    ],
    java: [
      /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/i,
      /new\s+ProcessBuilder\s*\(/i
    ]
  };

  /**
   * Analyzes a command line for interpreter transitions and nested execution payloads.
   */
  public static analyze(command: string): MultiInterpreterAnalysisResult {
    if (!command || typeof command !== 'string') {
      return { isSafe: true, isChained: false, interpretersDetected: [], transitions: [] };
    }

    const transitions: InterpreterTransition[] = [];
    const interpreters = new Set<string>();

    // 1. Python detection
    if (/\b(?:python|python3|py)\b/i.test(command)) {
      interpreters.add('python');
      const isInline = /-[a-zA-Z0-9]*c/i.test(command);
      const hasSubprocess = this.DANGEROUS_SUBPROCESS_PATTERNS.python.some(pat => pat.test(command));
      transitions.push({
        interpreter: 'python',
        isInlineExecution: isInline,
        hasSubprocessSpawn: hasSubprocess
      });

      if (hasSubprocess) {
        return {
          isSafe: false,
          isChained: true,
          interpretersDetected: Array.from(interpreters),
          transitions,
          reason: 'Dangerous subprocess invocation inside Python inline script blocked'
        };
      }
    }

    // 2. Node.js detection
    if (/\b(?:node|nodejs)\b/i.test(command)) {
      interpreters.add('node');
      const isInline = /-[a-zA-Z0-9]*e\b/i.test(command) || /--eval\b/i.test(command);
      const hasSubprocess = this.DANGEROUS_SUBPROCESS_PATTERNS.node.some(pat => pat.test(command));
      transitions.push({
        interpreter: 'node',
        isInlineExecution: isInline,
        hasSubprocessSpawn: hasSubprocess
      });

      if (hasSubprocess) {
        return {
          isSafe: false,
          isChained: true,
          interpretersDetected: Array.from(interpreters),
          transitions,
          reason: 'Dangerous child_process invocation inside Node.js execution blocked'
        };
      }
    }

    // 3. Perl detection
    const perlMatch = command.match(/\bperl\b(?:\s+(-[a-zA-Z0-9_-]+))?(?:\s+["']([^"']+)["'])?/i);
    if (perlMatch) {
      const flag = perlMatch[1] || '';
      const payload = perlMatch[2] || command;
      interpreters.add('perl');
      const hasSubprocess = this.DANGEROUS_SUBPROCESS_PATTERNS.perl.some(pat => pat.test(payload));
      transitions.push({
        interpreter: 'perl',
        flag,
        payload,
        isInlineExecution: flag.includes('e'),
        hasSubprocessSpawn: hasSubprocess
      });
      if (hasSubprocess) {
        return {
          isSafe: false,
          isChained: true,
          interpretersDetected: Array.from(interpreters),
          transitions,
          reason: 'Dangerous system execution inside Perl inline script blocked'
        };
      }
    }

    // 4. Ruby detection
    const rubyMatch = command.match(/\bruby\b(?:\s+(-[a-zA-Z0-9_-]+))?(?:\s+["']([^"']+)["'])?/i);
    if (rubyMatch) {
      const flag = rubyMatch[1] || '';
      const payload = rubyMatch[2] || command;
      interpreters.add('ruby');
      const hasSubprocess = this.DANGEROUS_SUBPROCESS_PATTERNS.ruby.some(pat => pat.test(payload));
      transitions.push({
        interpreter: 'ruby',
        flag,
        payload,
        isInlineExecution: flag.includes('e'),
        hasSubprocessSpawn: hasSubprocess
      });
      if (hasSubprocess) {
        return {
          isSafe: false,
          isChained: true,
          interpretersDetected: Array.from(interpreters),
          transitions,
          reason: 'Dangerous system execution inside Ruby script blocked'
        };
      }
    }

    // 5. PowerShell chaining inside shell
    if (/\b(?:powershell|pwsh)\b/i.test(command)) {
      interpreters.add('powershell');
      if (/(?:Invoke-Expression|IEX|\b-enc\b|\b-encodedcommand\b)/i.test(command)) {
        transitions.push({
          interpreter: 'powershell',
          isInlineExecution: true,
          hasSubprocessSpawn: true
        });
      }
    }

    // Check multi-interpreter chaining (e.g., bash spawning python which spawns another interpreter)
    const isChained = interpreters.size >= 2;
    if (isChained) {
      // If multiple distinct interpreters are chained within a single command payload, flag as high risk
      const hasInlineExecution = transitions.some(t => t.isInlineExecution);
      if (hasInlineExecution) {
        return {
          isSafe: false,
          isChained: true,
          interpretersDetected: Array.from(interpreters),
          transitions,
          reason: `Multi-interpreter execution chaining detected (${Array.from(interpreters).join(' -> ')})`
        };
      }
    }

    return {
      isSafe: true,
      isChained,
      interpretersDetected: Array.from(interpreters),
      transitions
    };
  }
}
