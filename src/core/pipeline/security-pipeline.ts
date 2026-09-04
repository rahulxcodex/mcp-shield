import { SecurityEvidence, ThreatCategory } from '../../security/evidence';
import { ToolCapabilities, CapabilityInferencer, CapabilityEvidence } from '../../security/capabilities';
import { UnicodeNormalizer } from '../../security/unicode-normalizer';
import { UnifiedInterpreterClassifier } from '../../security/interpreter-analyzer';
import { PathSecurityResolver } from '../../security/path-resolver';

export interface JsonRpcMessage {
  jsonrpc: string;
  id?: string | number | null;
  method?: string;
  params?: any;
  result?: any;
  error?: any;
}

export interface NormalizedInput {
  raw: any;
  toolName: string;
  rawArgs: Record<string, any>;
  candidateCommands: string[];
  candidatePaths: string[];
  isShellTool: boolean;
}

export interface MessageMetadata {
  receivedAt: number;
  sessionId: string;
  sourceIp?: string;
}

export interface RiskAssessment {
  score: number; // 0.0 to 1.0
  hardBlockTriggered: boolean;
  primaryViolation?: string;
}

export interface SecurityDecision {
  action: 'ALLOW' | 'BLOCK' | 'PROMPT' | 'SANDBOX' | 'SANITIZE';
  reason?: string;
  sanitizedArgs?: Record<string, any>;
}

export interface SecurityContext {
  request: JsonRpcMessage;
  normalizedInput: NormalizedInput;
  metadata: MessageMetadata;
  capabilities: {
    inferred: ToolCapabilities;
    declared: ToolCapabilities;
    effective: ToolCapabilities;
    evidence: CapabilityEvidence[];
  };
  evidence: SecurityEvidence[];
  risk: RiskAssessment;
  decision?: SecurityDecision;
  signal?: AbortSignal;
}

export interface SecurityDetector {
  readonly id: string;
  analyze(context: SecurityContext): Promise<SecurityEvidence[]> | SecurityEvidence[];
}

export class SecurityPipeline {
  private detectors: SecurityDetector[] = [];
  private interpreterClassifier = new UnifiedInterpreterClassifier();

  public registerDetector(detector: SecurityDetector): void {
    this.detectors.push(detector);
  }

  public async evaluate(
    request: JsonRpcMessage,
    metadata: MessageMetadata,
    signal?: AbortSignal
  ): Promise<SecurityContext> {
    if (signal?.aborted) {
      throw new Error('OPERATION_CANCELLED: Execution aborted before pipeline evaluation');
    }

    // Stage 1: Normalize
    const normalizedInput = this.normalizeStage(request);

    // Stage 2: Parse / Classify & Capability Extraction
    const capabilities = this.extractCapabilitiesStage(normalizedInput);

    const context: SecurityContext = {
      request,
      normalizedInput,
      metadata,
      capabilities,
      evidence: [],
      risk: {
        score: 0.0,
        hardBlockTriggered: false
      },
      signal
    };

    // Stage 3: Deterministic Detectors
    await this.runDeterministicDetectors(context);

    // Stage 4: Attack-path & Interpreter Analysis
    this.runAttackPathAnalysis(context);

    // Stage 5: Risk Scoring
    this.scoreRiskStage(context);

    // Stage 6: Policy Decision
    this.makePolicyDecisionStage(context);

    return context;
  }

  private normalizeStage(request: JsonRpcMessage): NormalizedInput {
    const params = request.params || {};
    const toolName = typeof params.name === 'string' ? params.name : '';
    const rawArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};

    const candidateCommands: string[] = [];
    const candidatePaths: string[] = [];

    const extractStrings = (obj: any, depth = 0) => {
      if (!obj || depth > 8) return;
      if (typeof obj === 'string') {
        const trimmed = obj.trim();
        if (trimmed) candidateCommands.push(trimmed);
        return;
      }
      if (Array.isArray(obj)) {
        for (const item of obj) extractStrings(item, depth + 1);
        return;
      }
      if (typeof obj === 'object') {
        for (const [k, v] of Object.entries(obj)) {
          const lower = k.toLowerCase();
          if (['command', 'cmd', 'script', 'code', 'exec', 'shell', 'payload', 'args'].includes(lower)) {
            if (typeof v === 'string' && v.trim()) candidateCommands.push(v.trim());
          } else if (['path', 'file', 'filename', 'filepath', 'dest', 'destination', 'targetpath'].includes(lower)) {
            if (typeof v === 'string' && v.trim()) candidatePaths.push(v.trim());
          }
          if (typeof v === 'object' && v !== null) {
            extractStrings(v, depth + 1);
          }
        }
      }
    };

    extractStrings(rawArgs);

    return {
      raw: request,
      toolName,
      rawArgs,
      candidateCommands,
      candidatePaths,
      isShellTool: /shell|bash|exec|terminal|run_command|eval/i.test(toolName)
    };
  }

  private extractCapabilitiesStage(input: NormalizedInput) {
    const schema = (input.raw?.params?._schema) || {};
    const resolved = CapabilityInferencer.resolveEffectiveCapabilities(
      input.toolName,
      schema,
      input.raw?.params?.description || ''
    );
    const inferred = CapabilityInferencer.infer(input.toolName, schema, input.raw?.params?.description || '');
    const declared = CapabilityInferencer.getDeclared(schema);

    return {
      inferred,
      declared,
      effective: resolved.effective,
      evidence: resolved.evidence
    };
  }

  private async runDeterministicDetectors(context: SecurityContext): Promise<void> {
    if (context.signal?.aborted) {
      throw new Error('OPERATION_CANCELLED: Aborted during detector execution');
    }

    // 1. Path Security Resolver check
    for (const rawPath of context.normalizedInput.candidatePaths) {
      const policyPath = PathSecurityResolver.resolveForPolicy(rawPath);
      if (policyPath.hasTraversalAttempt) {
        context.evidence.push({
          detectorId: 'path-security-resolver',
          category: 'PATH_TRAVERSAL',
          severity: 0.95,
          confidence: 0.98,
          hardBlock: true,
          features: { rawPath, canonical: policyPath.canonical },
          explanation: 'Directory traversal sequence detected in file parameter: ' + rawPath
        });
      }
    }

    // 2. Interpreter analysis for candidate commands
    for (const cmd of context.normalizedInput.candidateCommands) {
      const interpResult = this.interpreterClassifier.analyze(cmd);
      if (!interpResult.isSafe) {
        context.evidence.push(...interpResult.evidence);
      }
    }

    // 3. Run external/registered detectors
    for (const detector of this.detectors) {
      if (context.signal?.aborted) {
        throw new Error('OPERATION_CANCELLED: Aborted during detector execution');
      }
      const detectorEvidences = await detector.analyze(context);
      if (detectorEvidences && detectorEvidences.length > 0) {
        context.evidence.push(...detectorEvidences);
      }
    }
  }

  private runAttackPathAnalysis(context: SecurityContext): void {
    // Flag untrusted self-escalation attempts
    for (const capEv of context.capabilities.evidence) {
      if (capEv.source === 'remote-declaration' && capEv.trust === 'untrusted') {
        context.evidence.push({
          detectorId: 'capability-trust-engine',
          category: 'UNTRUSTED_CAPABILITY',
          severity: 0.7,
          confidence: 1.0,
          hardBlock: false,
          features: { capability: capEv.capability },
          explanation: "Untrusted tool declaration attempted self-grant of '" + capEv.capability + "' without admin policy"
        });
      }
    }
  }

  private scoreRiskStage(context: SecurityContext): void {
    let maxSeverity = 0.0;
    let hardBlock = false;
    let primaryViolation: string | undefined;

    for (const ev of context.evidence) {
      if (ev.severity > maxSeverity) {
        maxSeverity = ev.severity;
        primaryViolation = ev.explanation;
      }
      if (ev.hardBlock) {
        hardBlock = true;
        if (!primaryViolation) primaryViolation = ev.explanation;
      }
    }

    context.risk = {
      score: maxSeverity,
      hardBlockTriggered: hardBlock,
      primaryViolation
    };
  }

  private makePolicyDecisionStage(context: SecurityContext): void {
    if (context.risk.hardBlockTriggered || context.risk.score >= 0.8) {
      context.decision = {
        action: 'BLOCK',
        reason: context.risk.primaryViolation || 'Security policy violation detected (Fail-Closed)'
      };
    } else if (context.risk.score >= 0.5) {
      context.decision = {
        action: 'PROMPT',
        reason: context.risk.primaryViolation || 'High-risk operation requires human authorization'
      };
    } else {
      context.decision = {
        action: 'ALLOW'
      };
    }
  }
}
