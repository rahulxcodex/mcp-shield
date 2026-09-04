import { SecuritySession } from '../session';
import { CapabilityManifestRegistry, CapabilityBrokerDecision } from '../../security/capability-manifest';
import { ASTAnalyzer } from '../../security/ast-analyzer';
import { PowerShellASTAnalyzer } from '../../security/powershell-analyzer';
import { CmdAnalyzer } from '../../security/cmd-analyzer';
import { UnicodeNormalizer } from '../../security/unicode-normalizer';
import { MultiInterpreterAnalyzer } from '../../security/multi-interpreter-analyzer';
import { Evidence } from '../../security/policy-engine';
import { ToolCapabilities } from '../../security/capabilities';

export interface ToolSecurityAnalysisResult {
  isSafe: boolean;
  blockReason?: string;
  evidence: Evidence[];
  candidateCommands: string[];
}

export class ToolGuard {
  private astAnalyzer: ASTAnalyzer;
  private psAnalyzer: PowerShellASTAnalyzer;
  private cmdAnalyzer: CmdAnalyzer;
  private manifestRegistry: CapabilityManifestRegistry;

  constructor(
    private session: SecuritySession,
    manifestRegistry?: CapabilityManifestRegistry
  ) {
    this.astAnalyzer = new ASTAnalyzer();
    this.psAnalyzer = new PowerShellASTAnalyzer();
    this.cmdAnalyzer = new CmdAnalyzer(this.psAnalyzer);
    this.manifestRegistry = manifestRegistry || new CapabilityManifestRegistry(false);
  }

  public getManifestRegistry(): CapabilityManifestRegistry {
    return this.manifestRegistry;
  }

  public checkManifest(
    toolName: string,
    args: Record<string, any>,
    inferred: ToolCapabilities,
    isStrict: boolean
  ): CapabilityBrokerDecision {
    return this.manifestRegistry.verifyInvocation(toolName, args, inferred, { strictMode: isStrict });
  }

  public analyzeToolParameters(
    toolName: string,
    rawArgs: Record<string, any>,
    isShellTool: boolean = false
  ): ToolSecurityAnalysisResult {
    const evidence: Evidence[] = [];
    const candidateCommands: string[] = [];

    const extractCommands = (obj: any, depth = 0) => {
      if (!obj || depth > 8) return;
      if (typeof obj === 'string') {
        const trimmed = obj.trim();
        if (trimmed.length > 0) candidateCommands.push(trimmed);
        return;
      }
      if (Array.isArray(obj)) {
        for (const item of obj) extractCommands(item, depth + 1);
        return;
      }
      if (typeof obj === 'object') {
        for (const [k, v] of Object.entries(obj)) {
          const lower = k.toLowerCase();
          if (['command', 'cmd', 'script', 'code', 'exec', 'shell', 'query', 'payload', 'args', 'run', 'eval', 'instruction'].includes(lower)) {
            if (typeof v === 'string') candidateCommands.push(v.trim());
            else if (Array.isArray(v)) v.forEach((item) => typeof item === 'string' && candidateCommands.push(item.trim()));
          } else if (typeof v === 'object' && v !== null) {
            extractCommands(v, depth + 1);
          }
        }
      }
    };

    extractCommands(rawArgs);

    const shouldCheckAst = isShellTool || candidateCommands.length > 0;
    if (!shouldCheckAst || candidateCommands.length === 0) {
      return { isSafe: true, evidence, candidateCommands };
    }

    for (const cmd of candidateCommands) {
      // 0. Unicode canonicalization & evasion detection
      const unicodeAnalysis = UnicodeNormalizer.analyze(cmd);
      if (unicodeAnalysis.hasBidiOverrides || unicodeAnalysis.hasZeroWidth) {
        return {
          isSafe: false,
          blockReason: `Unicode evasion detected: ${unicodeAnalysis.violations.join('; ')}`,
          evidence,
          candidateCommands
        };
      }
      const normalizedCmd = unicodeAnalysis.normalized;

      // 0.1 Multi-interpreter and chaining detection
      const multiInterpResult = MultiInterpreterAnalyzer.analyze(normalizedCmd);
      if (!multiInterpResult.isSafe) {
        return {
          isSafe: false,
          blockReason: multiInterpResult.reason,
          evidence,
          candidateCommands
        };
      }

      // 1. Bash / POSIX AST
      const astResult = this.astAnalyzer.analyzeCommand(normalizedCmd);
      if (!astResult.isSafe) {
        return {
          isSafe: false,
          blockReason: astResult.reason,
          evidence,
          candidateCommands
        };
      }

      // 2. PowerShell AST
      const psResult = this.psAnalyzer.analyzeCommand(normalizedCmd);
      if (!psResult.isSafe) {
        return {
          isSafe: false,
          blockReason: psResult.reason,
          evidence,
          candidateCommands
        };
      }

      // 3. cmd.exe AST
      const cmdResult = this.cmdAnalyzer.analyzeCommand(normalizedCmd);
      if (!cmdResult.isSafe) {
        return {
          isSafe: false,
          blockReason: cmdResult.reason,
          evidence,
          candidateCommands
        };
      }
    }

    return {
      isSafe: true,
      evidence,
      candidateCommands
    };
  }
}
