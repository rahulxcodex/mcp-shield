/**
 * MCP Shield - Protocol-Neutral Agent Security Kernel
 * Step 3 Roadmap - Section 18 & Step 3 Completion Gate
 *
 * Core decoupled agent runtime executing universal security controls across:
 * - MCP Protocol Adapter
 * - Browser Protocol Adapter
 * - Coding Agent Protocol Adapter
 *
 * Provides shared security graph, policy, identity, attack paths, ML intelligence, DLP, and audit.
 */

import { SecurityEvidence } from '../evidence';
import { FeatureExtractor, FeatureVector } from '../ml/feature-extractor';
import { TabularRiskModel } from '../ml/models/tabular-risk-model';
import { TextSecurityClassifier } from '../ml/models/text-security-classifier';
import { BehaviorAnomalyDetector } from '../ml/models/behavior-anomaly-detector';
import { NoveltyScorer, NoveltyReport } from '../ml/novelty-scorer';
import { SecurityIntelligenceRegistry, SecurityIntelligenceVersion } from '../ml/intelligence-version';
import { PathSecurityResolver } from '../path-resolver';
import { Tier1MicroKernel } from '../../microkernel/fastpath/tier1-micro-kernel';
import { Tier2CausalEngine } from '../causal/tier2-causal-engine';

export type SupportedProtocol = 'mcp' | 'browser' | 'coding';

export interface CanonicalKernelRequest {
  protocol: SupportedProtocol;
  callerIdentity: string;
  actionName: string;
  parameters: Record<string, any>;
  candidateCommands: string[];
  candidatePaths: string[];
  candidateUrls: string[];
  destination?: string;
  metadata?: Record<string, any>;
}

export interface KernelSecurityDecision {
  action: 'ALLOW' | 'BLOCK' | 'PROMPT' | 'SANDBOX' | 'QUARANTINE';
  riskScore: number; // 0 to 100
  attackProbability: number; // 0.0 to 1.0
  hardBlockTriggered: boolean;
  reason?: string;
  evidence: SecurityEvidence[];
  novelty: NoveltyReport;
  intelligenceVersion: SecurityIntelligenceVersion;
  explainability: {
    primarySignals: string[];
    modelPredictions: {
      modelA: { risk: number; action: string };
      modelB?: { category: string; confidence: number };
      modelC?: { isAnomalous: boolean; anomalyScore: number };
    };
  };
}

export interface ProtocolAdapter {
  readonly protocol: SupportedProtocol;
  normalize(rawInput: any): CanonicalKernelRequest;
}

export class AgentSecurityKernel {
  private anomalyDetector = new BehaviorAnomalyDetector();
  private noveltyScorer = new NoveltyScorer();
  private adapters = new Map<SupportedProtocol, ProtocolAdapter>();

  public registerAdapter(adapter: ProtocolAdapter): void {
    this.adapters.set(adapter.protocol, adapter);
  }

  /**
   * Main evaluation entrypoint for canonical kernel requests
   */
  public async evaluate(request: CanonicalKernelRequest): Promise<KernelSecurityDecision> {
    const evidence: SecurityEvidence[] = [];
    let hardBlockTriggered = false;
    let primaryViolation: string | undefined;

    // 1. Deterministic Hard Controls: Path Traversal
    for (const p of request.candidatePaths) {
      const resolved = PathSecurityResolver.resolveForPolicy(p);
      if (resolved.hasTraversalAttempt) {
        hardBlockTriggered = true;
        primaryViolation = `Path traversal sequence detected in parameter: ${p}`;
        evidence.push({
          detectorId: 'kernel-path-resolver',
          category: 'PATH_TRAVERSAL',
          severity: 0.98,
          confidence: 1.0,
          hardBlock: true,
          features: { rawPath: p, canonical: resolved.canonical },
          explanation: primaryViolation
        });
      }
    }

    // 2. Deterministic Hard Controls: Shell Injections
    for (const cmd of request.candidateCommands) {
      if (/;\s*(?:rm\s+-rf|del\s+\/f|format\s+[c-z]:)|\|\s*(?:nc|curl|bash)|`.*?`/i.test(cmd)) {
        hardBlockTriggered = true;
        if (!primaryViolation) primaryViolation = `High-severity shell injection sequence detected: ${cmd}`;
        evidence.push({
          detectorId: 'kernel-command-analyzer',
          category: 'COMMAND_INJECTION',
          severity: 0.95,
          confidence: 0.98,
          hardBlock: true,
          features: { command: cmd },
          explanation: `Command injection syntax detected in '${cmd}'`
        });
      }
    }

    // 3. Online Novelty Scoring
    const novelty = this.noveltyScorer.evaluate({
      toolName: request.actionName,
      destination: request.destination,
      capabilities: request.metadata?.capabilities || []
    });

    // 4. Feature Extraction
    const features: FeatureVector = FeatureExtractor.extractFeatures({
      tool: {
        toolName: request.actionName,
        publisherTrustScore: request.metadata?.publisherTrust ?? 0.7,
        effectiveCapabilities: {
          filesystemRead: request.candidatePaths.length > 0,
          filesystemWrite: /write|save|create|put/i.test(request.actionName),
          shellExecution: request.candidateCommands.length > 0,
          networkAccess: Boolean(request.destination || request.candidateUrls.length > 0),
          processSpawn: /spawn|exec|bash|cmd/i.test(request.actionName),
          destructiveOperation: /delete|remove|rm|drop/i.test(request.actionName),
          secretAccess: /secret|key|vault|auth|token/i.test(request.actionName)
        }
      },
      request: {
        rawBody: request.parameters,
        extractedCommands: request.candidateCommands,
        extractedPaths: request.candidatePaths,
        candidateUrls: request.candidateUrls
      },
      behavior: {
        toolHistory: request.metadata?.toolHistory || []
      }
    });

    // 5. ML Model A: Tabular Risk Model
    const modelAPred = TabularRiskModel.predict(features);

    // 6. ML Model B: Text Security Classifier
    const stringifiedArgs = JSON.stringify(request.parameters);
    const modelBResult = TextSecurityClassifier.classify(stringifiedArgs, 'parameter');
    if (modelBResult.evidence) {
      evidence.push(modelBResult.evidence);
    }

    // 7. ML Model C: Behavioral Anomaly Detector
    const modelCResult = this.anomalyDetector.evaluateAction({
      currentTool: request.actionName,
      currentCapabilities: request.metadata?.capabilities || [],
      destination: request.destination
    });
    if (modelCResult.evidence) {
      evidence.push(modelCResult.evidence);
    }

    // 8. Tier 1 Fast-Path Microkernel Evaluation (<160us)
    const tier1Kernel = new Tier1MicroKernel();
    const t1Result = tier1Kernel.evaluate(stringifiedArgs);
    if (t1Result.blocked) {
      hardBlockTriggered = true;
      if (!primaryViolation) primaryViolation = `Tier 1 Fastpath: ${t1Result.reasons.join('; ')}`;
      evidence.push({
        detectorId: 'tier1-microkernel',
        category: 'PROTOCOL_VIOLATION',
        severity: t1Result.riskScore,
        confidence: 1.0,
        hardBlock: true,
        features: { motifs: t1Result.activeMotifs.join(',') },
        explanation: t1Result.reasons.join('; ')
      });
    }

    // 9. Unified Decision Fusion Contract (Iteration 5, Section 1)
    // S_fused = max(S_det, 0.35 * z_T1 + 0.65 * p_hat_T2)
    const sDet = hardBlockTriggered ? 1.0 : (primaryViolation ? 0.95 : 0.0);
    const zT1 = t1Result.riskScore;
    let posteriorBase = modelAPred.riskScore / 100;
    if (modelBResult.category !== 'BENIGN') {
      posteriorBase = Math.max(posteriorBase, modelBResult.severity);
    }
    if (modelCResult.isAnomalous) {
      posteriorBase = Math.max(posteriorBase, modelCResult.anomalyScore);
    }

    const fusedDecision = Tier2CausalEngine.fuseDecision(sDet, zT1, posteriorBase);
    const fusedRisk = Math.round(fusedDecision.fusedScore * 100);

    // Policy Decision
    let decisionAction: KernelSecurityDecision['action'] = 'ALLOW';
    if (fusedDecision.action !== 'MONITOR') {
      decisionAction = fusedDecision.action as KernelSecurityDecision['action'];
    }

    const intelVersion = SecurityIntelligenceRegistry.getActiveVersion();

    return {
      action: decisionAction,
      riskScore: fusedRisk,
      attackProbability: Math.min(1.0, fusedRisk / 100),
      hardBlockTriggered,
      reason: primaryViolation || (decisionAction !== 'ALLOW' ? `Elevated composite risk score: ${fusedRisk}/100` : undefined),
      evidence,
      novelty,
      intelligenceVersion: intelVersion,
      explainability: {
        primarySignals: [
          ...modelAPred.primarySignals,
          ...modelBResult.primarySignals,
          ...modelCResult.primarySignals
        ].filter(s => !s.includes('Standard benign')),
        modelPredictions: {
          modelA: { risk: modelAPred.riskScore, action: modelAPred.recommendedAction },
          modelB: { category: modelBResult.category, confidence: modelBResult.confidence },
          modelC: { isAnomalous: modelCResult.isAnomalous, anomalyScore: modelCResult.anomalyScore }
        }
      }
    };
  }
}
