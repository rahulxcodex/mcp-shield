import { SecurityCommandIR, SemanticThreatFinding, CommandInterpreterType } from './ir-types';
import { BashIRParser } from './parser/bash-ir-parser';
import { PowerShellIRParser } from './parser/powershell-ir-parser';
import { CmdIRParser } from './parser/cmd-ir-parser';
import { FilesystemSemanticExtractor } from './semantics/filesystem-extractor';
import { ProcessSemanticExtractor } from './semantics/process-extractor';
import { NetworkSemanticExtractor } from './semantics/network-extractor';

export interface IREvaluationResult {
  isSafe: boolean;
  ir: SecurityCommandIR;
  findings: SemanticThreatFinding[];
  maxSeverity: number;
  reason?: string;
}

export class SecurityIREngine {
  /**
   * Compiles raw command into normalized IR across supported interpreters
   */
  public static compileToIR(command: string, hint?: CommandInterpreterType): SecurityCommandIR {
    const cmd = command.trim();

    if (
      hint === 'POWERSHELL' ||
      /-(?:enc|encodedcommand|command)\b/i.test(cmd) ||
      /\b(?:Invoke-Expression|iex|Get-Content|iwr|Invoke-WebRequest|Invoke-RestMethod|irm|Remove-Item|ri|Get-ChildItem)\b/i.test(cmd)
    ) {
      return PowerShellIRParser.parse(cmd);
    }

    if (hint === 'CMD' || /%[a-zA-Z0-9_]+%/.test(cmd) || /\b(?:del|dir|type|erase|vssadmin)\b/i.test(cmd)) {
      return CmdIRParser.parse(cmd);
    }

    // Default to Bash / POSIX
    return BashIRParser.parse(cmd);
  }

  /**
   * Evaluates command via intermediate representation and semantic extractors
   */
  public static evaluate(command: string, hint?: CommandInterpreterType): IREvaluationResult {
    const ir = this.compileToIR(command, hint);

    const findings: SemanticThreatFinding[] = [
      ...FilesystemSemanticExtractor.extract(ir),
      ...ProcessSemanticExtractor.extract(ir),
      ...NetworkSemanticExtractor.extract(ir)
    ];

    const maxSeverity = findings.reduce((max, f) => Math.max(max, f.severity), 0);
    const isSafe = findings.length === 0 || maxSeverity < 0.7;

    return {
      isSafe,
      ir,
      findings,
      maxSeverity,
      reason: findings.length > 0 ? findings[0].explanation : undefined
    };
  }
}
