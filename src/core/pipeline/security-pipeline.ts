import { SecurityEvidence, ThreatCategory } from '../../security/evidence';
import { ToolCapabilities, CapabilityInferencer, CapabilityEvidence } from '../../security/capabilities';
import { UnicodeNormalizer } from '../../security/unicode-normalizer';
import { UnifiedInterpreterClassifier } from '../../security/interpreter-analyzer';
import { PathSecurityResolver } from '../../security/path-resolver';
import { FeatureExtractor, FeatureVector } from '../../security/ml/feature-extractor';
import { TabularRiskModel, ModelAPrediction } from '../../security/ml/models/tabular-risk-model';
import { TextSecurityClassifier, TextClassificationResult } from '../../security/ml/models/text-security-classifier';
import { BehaviorAnomalyDetector, AnomalyDetectionResult } from '../../security/ml/models/behavior-anomaly-detector';
import { NoveltyScorer, NoveltyReport } from '../../security/ml/novelty-scorer';
import { SchemaDriftDetector, SchemaDriftEvent } from '../../security/ml/schema-drift-detector';
import { SecurityIntelligenceRegistry, SecurityIntelligenceVersion } from '../../security/ml/intelligence-version';

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
  candidateUrls: string[];
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
  action: 'ALLOW' | 'BLOCK' | 'PROMPT' | 'SANDBOX' | 'SANITIZE' | 'QUARANTINE';
  reason?: string;
  sanitizedArgs?: Record<string, any>;
  requestId?: string;
  sessionId?: string;
  riskScore?: number;
  confidence?: number;
  detectorIds?: string[];
  explanation?: string;
  reasonCode?: string;
  enforcementSource?: 'deterministic' | 'policy' | 'ml' | 'composite';
  timestamp?: number;
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
  mlInsights?: {
    features?: FeatureVector;
    modelAPrediction?: ModelAPrediction;
    modelBClassification?: TextClassificationResult;
    modelCAnomaly?: AnomalyDetectionResult;
    novelty?: NoveltyReport;
    schemaDrift?: SchemaDriftEvent | null;
    intelligenceVersion?: SecurityIntelligenceVersion;
    shadowMode?: boolean;
  };
}

export interface SecurityDetector {
  readonly id: string;
  analyze(context: SecurityContext): Promise<SecurityEvidence[]> | SecurityEvidence[];
}

export class SecurityPipeline {
  private detectors: SecurityDetector[] = [];
  private interpreterClassifier = new UnifiedInterpreterClassifier();
  private noveltyScorer = new NoveltyScorer();
  private anomalyDetector = new BehaviorAnomalyDetector();
  private driftDetector = new SchemaDriftDetector();
  private shadowMode: boolean = false;

  public registerDetector(detector: SecurityDetector): void {
    this.detectors.push(detector);
  }

  public setShadowMode(enabled: boolean): void {
    this.shadowMode = enabled;
  }

  public isShadowMode(): boolean {
    return this.shadowMode;
  }

  public getNoveltyScorer(): NoveltyScorer {
    return this.noveltyScorer;
  }

  public getAnomalyDetector(): BehaviorAnomalyDetector {
    return this.anomalyDetector;
  }

  public getDriftDetector(): SchemaDriftDetector {
    return this.driftDetector;
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

    // Stage 5: ML Intelligence & Novelty Analysis
    this.runMlIntelligenceStage(context);

    // Stage 6: Risk Scoring & Hybrid Fusion
    this.scoreRiskStage(context);

    // Stage 7: Policy Decision
    this.makePolicyDecisionStage(context);

    return context;
  }

  private normalizeStage(request: JsonRpcMessage): NormalizedInput {
    const params = request.params || {};
    const toolName = typeof params.name === 'string' ? params.name : '';
    const rawArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};

    const candidateCommands: string[] = [];
    const candidatePaths: string[] = [];
    const candidateUrls: string[] = [];

    const extractStrings = (obj: any, depth = 0) => {
      if (!obj || depth > 8) return;
      if (typeof obj === 'string') {
        const trimmed = obj.trim();
        if (trimmed) {
          candidateCommands.push(trimmed);
          const urls = trimmed.match(/https?:\/\/[^\s"'>]+/gi);
          if (urls) candidateUrls.push(...urls);
        }
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
          } else if (['path', 'file', 'filename', 'filepath'].includes(lower)) {
            if (typeof v === 'string' && v.trim()) candidatePaths.push(v.trim());
          } else if (['url', 'uri', 'endpoint', 'dest', 'destination', 'webhook', 'target'].includes(lower)) {
            if (typeof v === 'string' && v.trim()) candidateUrls.push(v.trim());
          }
          if (typeof v === 'string') {
            const urls = v.match(/https?:\/\/[^\s"'>]+/gi);
            if (urls) candidateUrls.push(...urls);
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
      candidateUrls,
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

  private runMlIntelligenceStage(context: SecurityContext): void {
    const input = context.normalizedInput;
    const schema = (input.raw?.params?._schema) || {};
    const desc = input.raw?.params?.description || '';

    // 1. Schema Drift Check
    const drift = input.toolName ? this.driftDetector.evaluateDrift(input.toolName, schema, desc) : null;
    if (drift && drift.evidence) {
      context.evidence.push(drift.evidence);
    }

    // 2. Online Novelty Scoring
    const novelty = this.noveltyScorer.evaluate({
      toolName: input.toolName,
      schema,
      capabilities: Object.entries(context.capabilities.effective)
        .filter(([_, v]) => v)
        .map(([k]) => k)
    });

    // 3. Feature Extraction
    const features = FeatureExtractor.extractFeatures({
      tool: {
        toolName: input.toolName,
        schema,
        effectiveCapabilities: context.capabilities.effective,
        declaredCapabilities: context.capabilities.declared,
        inferredCapabilities: context.capabilities.inferred,
        hasSchemaDrift: Boolean(drift?.isHighRiskDrift)
      },
      request: {
        rawBody: input.rawArgs,
        extractedCommands: input.candidateCommands,
        extractedPaths: input.candidatePaths,
        candidateUrls: input.candidateUrls
      },
      behavior: {
        toolHistory: []
      }
    });

    // 4. Model A: Tabular Risk Model
    const modelAPrediction = TabularRiskModel.predict(features);

    // 5. Model B: Text Security Classifier
    const stringifiedArgs = JSON.stringify(input.rawArgs);
    const modelBClassification = TextSecurityClassifier.classify(stringifiedArgs, 'parameter');
    if (modelBClassification.evidence) {
      context.evidence.push(modelBClassification.evidence);
    }

    // 6. Model C: Behavioral Anomaly Detection
    const modelCAnomaly = this.anomalyDetector.evaluateAction({
      currentTool: input.toolName,
      currentCapabilities: Object.entries(context.capabilities.effective)
        .filter(([_, v]) => v)
        .map(([k]) => k)
    });
    if (modelCAnomaly.evidence) {
      context.evidence.push(modelCAnomaly.evidence);
    }

    context.mlInsights = {
      features,
      modelAPrediction,
      modelBClassification,
      modelCAnomaly,
      novelty,
      schemaDrift: drift,
      intelligenceVersion: SecurityIntelligenceRegistry.getActiveVersion(),
      shadowMode: this.shadowMode
    };
  }

  private scoreRiskStage(context: SecurityContext): void {
    let maxSeverity = 0.0;
    let hardBlock = false;
    let primaryViolation: string | undefined;

    // Evaluate deterministic evidence first
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

    // Incorporate ML Model A score if active and not in shadow mode
    if (context.mlInsights?.modelAPrediction) {
      const mlScoreNormalized = context.mlInsights.modelAPrediction.riskScore / 100.0;
      // Fundamental Invariant: ML may increase suspicion, never override hard block
      if (!this.shadowMode && mlScoreNormalized > maxSeverity) {
        maxSeverity = mlScoreNormalized;
        if (context.mlInsights.modelAPrediction.primarySignals.length > 0) {
          primaryViolation = context.mlInsights.modelAPrediction.primarySignals[0];
        }
      }
    }

    context.risk = {
      score: maxSeverity,
      hardBlockTriggered: hardBlock,
      primaryViolation
    };
  }

  private makePolicyDecisionStage(context: SecurityContext): void {
    const requestId = String(context.request.id ?? 'req-unknown');
    const sessionId = context.metadata.sessionId || 'session-default';
    const detectorIds = context.evidence.map(e => e.detectorId);
    const riskScore = context.risk.score;

    // Invariant: Deterministic hard block is strictly authoritative
    if (context.risk.hardBlockTriggered || context.risk.score >= 0.8) {
      const reason = context.risk.primaryViolation || 'Security policy violation detected (Fail-Closed)';
      context.decision = {
        action: 'BLOCK',
        reason,
        explanation: reason,
        reasonCode: context.risk.hardBlockTriggered ? 'HARD_BLOCK' : 'HIGH_RISK_BLOCK',
        requestId,
        sessionId,
        riskScore,
        detectorIds,
        enforcementSource: context.risk.hardBlockTriggered ? 'deterministic' : 'composite',
        timestamp: Date.now()
      };
    } else if (context.risk.score >= 0.5) {
      const reason = context.risk.primaryViolation || 'High-risk operation requires human authorization';
      context.decision = {
        action: 'PROMPT',
        reason,
        explanation: reason,
        reasonCode: 'AUTHORIZATION_REQUIRED',
        requestId,
        sessionId,
        riskScore,
        detectorIds,
        enforcementSource: 'policy',
        timestamp: Date.now()
      };
    } else {
      // Check if ML recommends stronger non-blocking action (SANDBOX or MONITOR)
      const mlAction = context.mlInsights?.modelAPrediction?.recommendedAction;
      if (!this.shadowMode && mlAction === 'SANDBOX') {
        const reason = 'ML risk model recommended sandboxed execution';
        context.decision = {
          action: 'SANDBOX',
          reason,
          explanation: reason,
          reasonCode: 'ML_SANDBOX_RECOMMENDED',
          requestId,
          sessionId,
          riskScore,
          detectorIds,
          enforcementSource: 'ml',
          timestamp: Date.now()
        };
      } else {
        context.decision = {
          action: 'ALLOW',
          reasonCode: 'ALLOW_POLICY',
          explanation: 'Request evaluated safe across all security detectors',
          requestId,
          sessionId,
          riskScore,
          detectorIds,
          enforcementSource: 'deterministic',
          timestamp: Date.now()
        };
      }
    }
  }
}

