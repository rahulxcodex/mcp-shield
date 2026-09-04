/**
 * MCP Shield - Model Evaluation Framework
 * Step 3 Roadmap - Section 10, Section 11 & Milestone B, Milestone E
 *
 * Implements rigorous evaluation methodologies:
 * - Temporal holdout evaluation (train historical, test future)
 * - Server holdout evaluation (train on servers A/B/C, test unseen D/E)
 * - Attack-family holdout evaluation (train omitting family, test generalization)
 *
 * Measures:
 * - Precision, Recall, FPR, FNR, F1 Score
 * - ROC-AUC, PR-AUC, Brier Calibration Score
 * - Latency (P50, P95, P99)
 * - Threat-Class Confusion Matrix
 */

import { TabularRiskModel, ModelAPrediction } from '../models/tabular-risk-model';
import { FeatureVector } from '../feature-extractor';

export interface LabeledSample {
  id: string;
  timestamp: number;
  server: string;
  attackFamily?: string; // e.g. 'COMMAND_INJECTION', 'SSRF', 'PATH_TRAVERSAL', 'BENIGN'
  isAttack: boolean;
  features: FeatureVector;
}

export interface EvaluationMetrics {
  sampleCount: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  fpr: number;
  fnr: number;
  f1Score: number;
  rocAuc: number;
  prAuc: number;
  brierScore: number; // Mean squared error of probability vs actual outcome (0.0 = perfect calibration)
  latencyP50Us: number;
  latencyP95Us: number;
  latencyP99Us: number;
  confusionMatrixByFamily: Record<string, { total: number; detected: number; rate: number }>;
}

export class ModelEvaluator {
  /**
   * Evaluates a set of labeled samples against TabularRiskModel
   */
  public static evaluate(samples: LabeledSample[], decisionThreshold = 0.5): EvaluationMetrics {
    if (samples.length === 0) {
      throw new Error('Cannot evaluate empty sample set');
    }

    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let brierSum = 0;
    const latencies: number[] = [];
    const scoresAndLabels: Array<{ score: number; isAttack: boolean }> = [];
    const familyCounts: Record<string, { total: number; detected: number }> = {};

    for (const sample of samples) {
      const pred: ModelAPrediction = TabularRiskModel.predict(sample.features);
      latencies.push(pred.inferenceLatencyUs);

      const actual = sample.isAttack ? 1 : 0;
      const prob = pred.attackProbability;
      brierSum += Math.pow(prob - actual, 2);

      scoresAndLabels.push({ score: prob, isAttack: sample.isAttack });

      const predictedAttack = prob >= decisionThreshold;

      if (predictedAttack && sample.isAttack) tp++;
      else if (predictedAttack && !sample.isAttack) fp++;
      else if (!predictedAttack && !sample.isAttack) tn++;
      else if (!predictedAttack && sample.isAttack) fn++;

      // Track by attack family
      const family = sample.attackFamily || (sample.isAttack ? 'UNKNOWN_ATTACK' : 'BENIGN');
      if (!familyCounts[family]) {
        familyCounts[family] = { total: 0, detected: 0 };
      }
      familyCounts[family].total++;
      if (predictedAttack) familyCounts[family].detected++;
    }

    // Sort latencies for percentiles
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.50)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    // Standard classification metrics
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 1.0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 1.0;
    const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0.0;
    const fnr = (tp + fn) > 0 ? fn / (tp + fn) : 0.0;
    const f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;
    const brierScore = brierSum / samples.length;

    // ROC-AUC and PR-AUC approximation via trapezoidal integration
    const { rocAuc, prAuc } = this.calculateAucMetrics(scoresAndLabels);

    const confusionMatrixByFamily: Record<string, { total: number; detected: number; rate: number }> = {};
    for (const [family, counts] of Object.entries(familyCounts)) {
      confusionMatrixByFamily[family] = {
        total: counts.total,
        detected: counts.detected,
        rate: counts.total > 0 ? Math.round((counts.detected / counts.total) * 100) / 100 : 0
      };
    }

    return {
      sampleCount: samples.length,
      tp,
      fp,
      tn,
      fn,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      fpr: Math.round(fpr * 1000) / 1000,
      fnr: Math.round(fnr * 1000) / 1000,
      f1Score: Math.round(f1Score * 1000) / 1000,
      rocAuc: Math.round(rocAuc * 1000) / 1000,
      prAuc: Math.round(prAuc * 1000) / 1000,
      brierScore: Math.round(brierScore * 1000) / 1000,
      latencyP50Us: p50,
      latencyP95Us: p95,
      latencyP99Us: p99,
      confusionMatrixByFamily
    };
  }

  /**
   * Computes ROC-AUC and PR-AUC across ranked threshold sweeps
   */
  private static calculateAucMetrics(items: Array<{ score: number; isAttack: boolean }>): { rocAuc: number; prAuc: number } {
    items.sort((a, b) => b.score - a.score);

    const posCount = items.filter(i => i.isAttack).length;
    const negCount = items.length - posCount;

    if (posCount === 0 || negCount === 0) {
      return { rocAuc: 1.0, prAuc: 1.0 };
    }

    let tp = 0;
    let fp = 0;
    let rocAuc = 0;
    let prAuc = 0;
    let lastTpr = 0;
    let lastFpr = 0;
    let lastRecall = 0;

    for (const item of items) {
      if (item.isAttack) tp++;
      else fp++;

      const tpr = tp / posCount;
      const currentFpr = fp / negCount;
      const precision = tp / (tp + fp);

      // Trapezoid for ROC
      rocAuc += (currentFpr - lastFpr) * (tpr + lastTpr) / 2;
      // Trapezoid for PR
      prAuc += (tpr - lastRecall) * precision;

      lastTpr = tpr;
      lastFpr = currentFpr;
      lastRecall = tpr;
    }

    return {
      rocAuc: Math.min(1.0, Math.max(0.0, rocAuc)),
      prAuc: Math.min(1.0, Math.max(0.0, prAuc))
    };
  }

  /**
   * Splits dataset for temporal holdout evaluation
   */
  public static splitTemporal(samples: LabeledSample[], splitRatio = 0.7): { train: LabeledSample[]; test: LabeledSample[] } {
    const sorted = [...samples].sort((a, b) => a.timestamp - b.timestamp);
    const splitIndex = Math.floor(sorted.length * splitRatio);
    return {
      train: sorted.slice(0, splitIndex),
      test: sorted.slice(splitIndex)
    };
  }

  /**
   * Splits dataset for server holdout evaluation
   */
  public static splitServer(samples: LabeledSample[], holdoutServers: string[]): { train: LabeledSample[]; test: LabeledSample[] } {
    const holdoutSet = new Set(holdoutServers);
    return {
      train: samples.filter(s => !holdoutSet.has(s.server)),
      test: samples.filter(s => holdoutSet.has(s.server))
    };
  }

  /**
   * Splits dataset for attack-family holdout evaluation
   */
  public static splitAttackFamily(samples: LabeledSample[], holdoutFamily: string): { train: LabeledSample[]; test: LabeledSample[] } {
    return {
      train: samples.filter(s => s.attackFamily !== holdoutFamily),
      test: samples.filter(s => s.attackFamily === holdoutFamily)
    };
  }
}
