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

import { SecurityEvidence, ThreatCategory } from '../evidence';
import { FeatureExtractor, FeatureVector } from '../ml/feature-extractor';
import { TabularRiskModel, ModelAPrediction } from '../ml/models/tabular-risk-model';
import { TextSecurityClassifier } from '../ml/models/text-security-classifier';
import { BehaviorAnomalyDetector } from '../ml/models/behavior-anomaly-detector';
import { NoveltyScorer, NoveltyReport } from '../ml/novelty-scorer';
import { SecurityIntelligenceRegistry, SecurityIntelligenceVersion } from '../ml/intelligence-version';
import { PathSecurityResolver } from '../path-resolver';

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

    // Calculate fused risk score
    // Invariant: Deterministic hard block is authoritative!
    let fusedRisk = modelAPred.riskScore;
    if (modelBResult.category !== 'BENIGN') {
      fusedRisk = Math.max(fusedRisk, Math.round(modelBResult.severity * 100));
    }
    if (modelCResult.isAnomalous) {
      fusedRisk = Math.max(fusedRisk, Math.round(modelCResult.anomalyScore * 80));
    }
    if (hardBlockTriggered) {
      fusedRisk = Math.max(fusedRisk, 95);
    }

    // Policy Decision
    let decisionAction: KernelSecurityDecision['action'] = 'ALLOW';
    if (hardBlockTriggered || fusedRisk >= 85) {
      decisionAction = 'BLOCK';
    } else if (fusedRisk >= 70) {
      decisionAction = 'QUARANTINE';
    } else if (fusedRisk >= 55) {
      decisionAction = 'SANDBOX';
    } else if (fusedRisk >= 40) {
      decisionAction = 'PROMPT';
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
