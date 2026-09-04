import { SecuritySession } from '../session';
import { CapabilityManifestRegistry, CapabilityBrokerDecision } from '../../security/capability-manifest';
import { ASTAnalyzer } from '../../security/ast-analyzer';
import { PowerShellASTAnalyzer } from '../../security/powershell-analyzer';
import { CmdAnalyzer } from '../../security/cmd-analyzer';
import { UnicodeNormalizer } from '../../security/unicode-normalizer';
import { MultiInterpreterAnalyzer } from '../../security/multi-interpreter-analyzer';
import { Evidence } from '../../security/policy-engine';
import { ToolCapabilities } from '../../security/capabilities';
import { UnifiedInterpreterClassifier } from '../../security/interpreter-analyzer';

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
  private interpreterClassifier: UnifiedInterpreterClassifier;

  constructor(
    private session: SecuritySession,
    manifestRegistry?: CapabilityManifestRegistry
  ) {
    this.astAnalyzer = new ASTAnalyzer();
    this.psAnalyzer = new PowerShellASTAnalyzer();
    this.cmdAnalyzer = new CmdAnalyzer(this.psAnalyzer);
    this.manifestRegistry = manifestRegistry || new CapabilityManifestRegistry(false);
    this.interpreterClassifier = new UnifiedInterpreterClassifier();
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

      const interpResult = this.interpreterClassifier.analyze(normalizedCmd);
      if (!interpResult.isSafe) {
        return {
          isSafe: false,
          blockReason: interpResult.reason,
          evidence: [
            ...evidence,
            ...interpResult.evidence.map(e => ({
              detector: e.detectorId,
              finding: e.explanation,
              risk: (e.severity >= 0.8 ? 'CRITICAL' : e.severity >= 0.6 ? 'HIGH' : 'MEDIUM') as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
            }))
          ],
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
