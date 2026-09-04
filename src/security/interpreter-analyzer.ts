import { SecurityEvidence, ThreatCategory } from './evidence';
import { ASTAnalyzer } from './ast-analyzer';
import { PowerShellASTAnalyzer } from './powershell-analyzer';
import { CmdAnalyzer } from './cmd-analyzer';
import { UnicodeNormalizer } from './unicode-normalizer';
import { MultiInterpreterAnalyzer } from './multi-interpreter-analyzer';

export interface NormalizedCommand {
  raw: string;
  normalized: string;
  tokens: string[];
}

export interface InterpreterEvidence {
  interpreter: string;
  isSafe: boolean;
  reason?: string;
  evidence: SecurityEvidence[];
}

export interface InterpreterAnalyzer {
  readonly id: string;
  readonly supportedInterpreters: string[];
  supports(input: NormalizedCommand): boolean;
  analyze(input: NormalizedCommand): InterpreterEvidence;
}

export class BashInterpreterAnalyzer implements InterpreterAnalyzer {
  public readonly id = 'bash-interpreter-analyzer';
  public readonly supportedInterpreters = ['bash', 'sh', 'zsh', 'dash', 'ksh', 'posix'];
  private astAnalyzer = new ASTAnalyzer();

  public supports(input: NormalizedCommand): boolean {
    const first = (input.tokens[0] || '').toLowerCase();
    const base = first.split(/[\/\\]/).pop() || '';
    if (this.supportedInterpreters.includes(base)) {
      return true;
    }
    // Default fallback for general UNIX CLI commands if not powershell or cmd
    const isWindowsInterpreter = ['powershell', 'pwsh', 'cmd', 'cmd.exe'].includes(base);
    const hasWindowsSyntax = input.normalized.includes('%') || /-(?:enc|encodedcommand|command|e):/i.test(input.normalized);
    return !isWindowsInterpreter && !hasWindowsSyntax;
  }

  public analyze(input: NormalizedCommand): InterpreterEvidence {
    const result = this.astAnalyzer.analyzeCommand(input.normalized);
    const evidence: SecurityEvidence[] = [];

    if (!result.isSafe) {
      evidence.push({
        detectorId: this.id,
        category: 'COMMAND_INJECTION',
        severity: 0.9,
        confidence: 0.95,
        hardBlock: true,
        features: { interpreter: 'bash', isParseError: !!result.isParseError },
        explanation: result.reason || 'Bash AST security policy violation'
      });
    }

    return {
      interpreter: 'bash',
      isSafe: result.isSafe,
      reason: result.reason,
      evidence
    };
  }
}

export class PowerShellInterpreterAnalyzer implements InterpreterAnalyzer {
  public readonly id = 'powershell-interpreter-analyzer';
  public readonly supportedInterpreters = ['powershell', 'pwsh'];
  private psAnalyzer = new PowerShellASTAnalyzer();

  public supports(input: NormalizedCommand): boolean {
    const first = (input.tokens[0] || '').toLowerCase();
    const base = first.split(/[\/\\]/).pop() || '';
    if (this.supportedInterpreters.includes(base)) {
      return true;
    }

    // PowerShell specific flags and cmdlets
    const cmd = input.normalized;
    if (/-(?:enc|encodedcommand|command|file|ex|executionpolicy)\b/i.test(cmd)) {
      return true;
    }
    if (/\b(?:invoke-expression|iex|invoke-webrequest|iwr|start-process|get-process|get-content|set-content|out-file|select-object|downloadstring|downloadfile)\b/i.test(cmd)) {
      return true;
    }
    if (/\[[a-zA-Z0-9_.]+(?:::|\])/.test(cmd)) {
      return true; // .NET type accelerator e.g. [System.Net.WebClient]
    }
    return false;
  }

  public analyze(input: NormalizedCommand): InterpreterEvidence {
    const result = this.psAnalyzer.analyzeCommand(input.normalized);
    const evidence: SecurityEvidence[] = [];

    if (!result.isSafe) {
      evidence.push({
        detectorId: this.id,
        category: 'COMMAND_INJECTION',
        severity: 0.95,
        confidence: 0.95,
        hardBlock: true,
        features: { interpreter: 'powershell' },
        explanation: result.reason || 'PowerShell AST security policy violation'
      });
    }

    return {
      interpreter: 'powershell',
      isSafe: result.isSafe,
      reason: result.reason,
      evidence
    };
  }
}

export class CmdInterpreterAnalyzer implements InterpreterAnalyzer {
  public readonly id = 'cmd-interpreter-analyzer';
  public readonly supportedInterpreters = ['cmd', 'cmd.exe'];
  private cmdAnalyzer: CmdAnalyzer;

  constructor() {
    this.cmdAnalyzer = new CmdAnalyzer(new PowerShellASTAnalyzer());
  }

  public supports(input: NormalizedCommand): boolean {
    const first = (input.tokens[0] || '').toLowerCase();
    const base = first.split(/[\/\\]/).pop() || '';
    if (this.supportedInterpreters.includes(base)) {
      return true;
    }

    const cmd = input.normalized;
    if (/%[a-zA-Z0-9_]+%/.test(cmd)) {
      return true; // cmd %VAR% expansion
    }
    if (/\b(?:cmd|cmd\.exe)\b/i.test(cmd)) {
      return true;
    }
    if (['dir', 'del', 'erase', 'rmdir', 'rd', 'copy', 'xcopy', 'robocopy', 'type', 'ren', 'rename', 'cls', 'attrib'].includes(base)) {
      return true;
    }
    if (/\b(?:del|erase|rmdir|rd|copy|xcopy|robocopy|type|ren|rename|dir)\s+[\/\\]/i.test(cmd)) {
      return true;
    }
    return false;
  }

  public analyze(input: NormalizedCommand): InterpreterEvidence {
    const result = this.cmdAnalyzer.analyzeCommand(input.normalized);
    const evidence: SecurityEvidence[] = [];

    if (!result.isSafe) {
      evidence.push({
        detectorId: this.id,
        category: 'COMMAND_INJECTION',
        severity: 0.9,
        confidence: 0.9,
        hardBlock: true,
        features: { interpreter: 'cmd' },
        explanation: result.reason || 'cmd.exe lexical security violation'
      });
    }

    return {
      interpreter: 'cmd',
      isSafe: result.isSafe,
      reason: result.reason,
      evidence
    };
  }
}

export class UnifiedInterpreterClassifier {
  private analyzers: InterpreterAnalyzer[] = [
    new PowerShellInterpreterAnalyzer(),
    new CmdInterpreterAnalyzer(),
    new BashInterpreterAnalyzer()
  ];

  public normalize(rawCommand: string): NormalizedCommand {
    const unicodeResult = UnicodeNormalizer.analyze(rawCommand);
    const normalized = unicodeResult.normalized;
    const tokens = normalized.trim().split(/\s+/);
    return {
      raw: rawCommand,
      normalized,
      tokens
    };
  }

  /**
   * Dispatches command analysis to ONLY the matching interpreter analyzer(s),
   * eliminating duplicate parsing and redundant execution.
   */
  public analyze(rawCommand: string): InterpreterEvidence {
    const input = this.normalize(rawCommand);
    const allEvidence: SecurityEvidence[] = [];

    // 1. Chaining and multi-interpreter transition check
    const multiResult = MultiInterpreterAnalyzer.analyze(input.normalized);
    if (!multiResult.isSafe) {
      allEvidence.push({
        detectorId: 'multi-interpreter-analyzer',
        category: 'COMMAND_INJECTION',
        severity: 0.95,
        confidence: 0.98,
        hardBlock: true,
        features: {
          isChained: multiResult.isChained,
          interpreters: multiResult.interpretersDetected.join(',')
        },
        explanation: multiResult.reason || 'Multi-interpreter execution chaining blocked'
      });
      return {
        interpreter: 'multi-interpreter',
        isSafe: false,
        reason: multiResult.reason,
        evidence: allEvidence
      };
    }

    // 2. Select matching interpreter analyzer
    let matchedAnalyzer: InterpreterAnalyzer | undefined;
    for (const analyzer of this.analyzers) {
      if (analyzer.supports(input)) {
        matchedAnalyzer = analyzer;
        break;
      }
    }

    if (!matchedAnalyzer) {
      matchedAnalyzer = this.analyzers[this.analyzers.length - 1]; // Fallback to Bash
    }

    const result = matchedAnalyzer.analyze(input);
    return {
      interpreter: result.interpreter,
      isSafe: result.isSafe,
      reason: result.reason,
      evidence: [...allEvidence, ...result.evidence]
    };
  }
}
