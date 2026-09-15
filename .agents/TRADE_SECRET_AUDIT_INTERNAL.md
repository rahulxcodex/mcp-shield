# MCP-Shield Trade Secret Audit — Internal IP Analysis

> **CONFIDENTIAL — NOT FOR GITHUB**
> This document is stored in `.agents/` which is `.gitignore`'d.
> It audits the public `mcp-shield` codebase for additional intellectual property
> that could be elevated to trade secret status.

**Audit Date**: September 2026
**Auditor**: Internal IP Review
**Scope**: `mcp-shield` public repository (GitHub `rahulxcodex/mcp-shield`)

---

## 1. Currently Protected Trade Secrets

The following IP is already isolated in private repositories behind the trade secret boundary:

| Trade Secret | Private Repository | Location |
| :--- | :--- | :--- |
| Non-linear risk scoring algorithm | `mcp-shield-enterprise-intel` | `src/intel/risk-engine.ts` |
| Risk scoring constants (`AST_COMPLEXITY_EXPONENT = 1.35`, `EGRESS_SEVERITY_MULTIPLIER = 2.45`, `DRIFT_BASE_PENALTY = 35.0`) | `mcp-shield-enterprise-intel` | `src/intel/risk-engine.ts` |
| Weaponized attack corpus & behavioral kill chains (`CHAIN-EXFIL-001`, `CHAIN-STAGE-DETONATE-001`) | `mcp-shield-enterprise-intel` | `src/intel/threat-corpus/` |
| Behavioral suffix trie (`BehavioralChainTrie`) | `mcp-shield-enterprise-intel` | `src/intel/risk-engine.ts` |
| Ed25519 private signing key | `mcp-shield-licensing` | Vercel KMS (`LICENSE_PRIVATE_KEY`) |
| License generation logic & Stripe billing | `mcp-shield-licensing` | `api/license.ts` |
| ML model training data & Colab notebooks | `mcp-shield-enterprise-intel` | `notebooks/` |

**Status**: All of the above are correctly isolated. The public repo contains only the verification side (Ed25519 public key) and API client stubs.

---

## 2. Candidates for Trade Secret Elevation

The following code currently resides in the **public** `mcp-shield` repository but may qualify for trade secret protection based on competitive advantage, reverse-engineering risk, and business value.

### 2.1 TabularRiskModel Feature Engineering (HIGH PRIORITY)

**File**: `src/security/ml/tabular-risk-model.ts`
**What**: The 42 versioned feature vectors extracted from tool invocations for risk scoring. The feature selection process (VIF thresholds, correlation analysis, information gain ranking) represents significant R&D investment.
**Risk if disclosed**: A competitor could replicate the exact feature set and train a competing model without the R&D cost.
**Recommendation**: **PROTECT** — Move the feature extraction logic and feature names behind the `enterprise-intel` API. The public repo should send raw tool invocation data to the scoring endpoint rather than performing local feature engineering.

### 2.2 AdversarialLearningLoop Training Pipeline

**File**: `src/security/ml/adversarial-learning-loop.ts`
**What**: The feedback loop that ingests community bypass submissions, generates adversarial mutations, and retrains detection models. Includes mutation families, variant templates, and training hyperparameters.
**Risk if disclosed**: Attackers could study the mutation families to craft evasions outside the generator's coverage.
**Recommendation**: **PROTECT** — The loop orchestration can stay public (it's essentially a training script), but the mutation family definitions and variant templates should move to `enterprise-intel`.

### 2.3 BehaviorAnomalyDetector Markov Thresholds

**File**: `src/security/ml/behavior-anomaly-detector.ts`
**What**: The Markov chain transition probability thresholds used to distinguish normal vs. anomalous tool-calling sequences. These were tuned on real-world telemetry data.
**Risk if disclosed**: An attacker could craft tool-calling sequences that stay just under the anomaly thresholds.
**Recommendation**: **PROTECT** — Move the threshold constants to `enterprise-intel`. The public code should call the scoring endpoint for anomaly verdicts.

### 2.4 NoveltyScorer Distance Metrics & Outlier Thresholds

**File**: `src/security/ml/novelty-scorer.ts`
**What**: The specific distance metrics (Mahalanobis, cosine, etc.) and outlier decision thresholds for identifying previously unseen attack patterns.
**Risk if disclosed**: Attackers could compute their distance from the decision boundary and adjust payloads.
**Recommendation**: **PROTECT** — Move distance computation and thresholds to `enterprise-intel`.

### 2.5 BlastRadiusEngine 7-Vector Weights

**File**: `src/security/blast-radius/blast-radius-engine.ts`
**What**: The 7-vector computation weights used to estimate worst-case impact of a tool invocation. These weights determine which risk signals dominate the blast radius score.
**Risk if disclosed**: Competitors could replicate the impact scoring without R&D investment.
**Recommendation**: **PROTECT** — Move weight constants to `enterprise-intel`. The public engine should delegate weight lookups to the scoring endpoint.

### 2.6 IntelligenceBus Fusion Weights & Precedence Rules

**File**: `src/security/intelligence/intelligence-bus.ts`
**What**: The typed signal fusion weights and hard-block precedence ordering that determine how multiple detector signals combine into a unified security decision.
**Risk if disclosed**: Understanding the precedence rules could help attackers identify which detectors to evade vs. which are overridable.
**Recommendation**: **PROTECT** — Move the fusion weight table and precedence ordering to `enterprise-intel`.

### 2.7 LMAX Disruptor Ring Buffer Configuration

**File**: `src/microkernel/ring-buffer/lmax-disruptor.ts`
**What**: Ring buffer sizing, NUMA pinning configuration, and wait strategy parameters tuned for specific hardware profiles.
**Risk if disclosed**: Moderate — primarily a performance optimization, not a security advantage.
**Recommendation**: **MONITOR** — Keep public for now. These are performance tuning constants with limited competitive moat. Re-evaluate if the microkernel becomes a selling point.

### 2.8 Tier 1 Micro-Kernel Fast-Path Constants

**File**: `src/microkernel/fastpath/tier1-micro-kernel.ts`
**What**: INT8 quantization parameters, GroupSort-2 activation constants, and SIMD batch sizes for the ultra-low-latency fast-path.
**Risk if disclosed**: These are performance-critical constants that represent significant tuning effort.
**Recommendation**: **PROTECT** — Move quantization and activation constants to `enterprise-intel`. The fast-path architecture can remain public.

### 2.9 GroupSort-DSCNN Activation Parameters

**File**: `src/microkernel/fastpath/groupsort-dscnn.ts`
**What**: GroupSort-2 activation function parameters and depthwise separable convolution kernel configurations.
**Risk if disclosed**: These represent novel neural architecture choices for security classification.
**Recommendation**: **PROTECT** — Move to `enterprise-intel`.

### 2.10 ModelGovernanceRegistry Promotion Gates

**File**: `src/security/ml/model-governance-registry.ts`
**What**: Shadow → canary → production promotion thresholds (accuracy, latency, false-positive rate gates).
**Risk if disclosed**: Low — standard MLOps practice. The thresholds themselves aren't a competitive moat.
**Recommendation**: **MONITOR** — Keep public. Standard MLOps patterns.

### 2.11 CustomerFuzzer Attack Path Heuristics

**File**: `src/security/attack-path/customer-fuzzer.ts`
**What**: Heuristics for discovering customer-specific attack paths through policy configurations.
**Risk if disclosed**: An attacker could study the heuristics to understand which attack paths the system is optimized to find.
**Recommendation**: **PROTECT** — Move the path discovery heuristics to `enterprise-intel`. The public interface should accept policy configs and return discovered paths.

### 2.12 SchemaDriftDetector Classification Categories

**File**: `src/security/ml/schema-drift-detector.ts`
**What**: The specific drift categories, severity classifications, and policy-to-action mappings.
**Risk if disclosed**: Low — drift categories are somewhat self-evident from the MCP protocol spec.
**Recommendation**: **MONITOR** — Keep public. The categories follow naturally from the MCP specification.

### 2.13 TextSecurityClassifier Vocabulary & Embeddings

**File**: `src/security/ml/text-security-classifier.ts`
**What**: The security-specific vocabulary, embedding weights, and classification thresholds for analyzing tool descriptions.
**Risk if disclosed**: Attackers could craft tool descriptions that bypass the classifier.
**Recommendation**: **PROTECT** — Move vocabulary, embeddings, and thresholds to `enterprise-intel`.

---

## 3. Risk Assessment Summary

| # | Candidate | Business Impact if Disclosed | Reverse-Engineering Feasibility | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| 2.1 | TabularRiskModel features | **HIGH** — replicates years of R&D | Medium (observable via telemetry) | **PROTECT** |
| 2.2 | AdversarialLearningLoop mutations | **HIGH** — enables evasion engineering | Low (requires access) | **PROTECT** |
| 2.3 | BehaviorAnomaly thresholds | **HIGH** — enables threshold-aware attacks | Low | **PROTECT** |
| 2.4 | NoveltyScorer metrics | **MEDIUM** — enables boundary-aware crafting | Low | **PROTECT** |
| 2.5 | BlastRadius weights | **MEDIUM** — competitive replication | Medium | **PROTECT** |
| 2.6 | IntelligenceBus fusion | **HIGH** — reveals detector hierarchy | Low | **PROTECT** |
| 2.7 | LMAX Disruptor config | **LOW** — performance only | High (standard tuning) | MONITOR |
| 2.8 | Tier 1 fast-path constants | **MEDIUM** — novel architecture | Low | **PROTECT** |
| 2.9 | GroupSort-DSCNN params | **MEDIUM** — novel ML architecture | Low | **PROTECT** |
| 2.10 | ModelGovernance gates | **LOW** — standard MLOps | High | MONITOR |
| 2.11 | CustomerFuzzer heuristics | **HIGH** — attack surface insight | Low | **PROTECT** |
| 2.12 | SchemaDrift categories | **LOW** — protocol-driven | High | MONITOR |
| 2.13 | TextClassifier vocab | **HIGH** — enables evasion | Low | **PROTECT** |

---

## 4. Recommended Actions

### Immediate (Next Sprint)

1. **Extract ML constants**: Move all threshold constants, feature names, and weight values from `src/security/ml/*.ts` into environment variables or runtime-fetched configuration from `enterprise-intel`.
2. **Refactor IntelligenceBus**: Replace hardcoded fusion weights with a `GET /api/v1/intel/fusion-config` endpoint on `enterprise-intel`.
3. **Move mutation families**: Transfer `AdversarialGenerator` mutation templates to `enterprise-intel/src/intel/adversarial/`.

### Short-Term (Next Quarter)

4. **Extract blast-radius weights**: Delegate blast-radius computation to `enterprise-intel` scoring endpoint.
5. **Move fast-path constants**: Transfer Tier 1 quantization and GroupSort parameters to `enterprise-intel`.
6. **CustomerFuzzer API boundary**: Create a `POST /api/v1/intel/attack-paths` endpoint to centralize heuristic logic.

### Ongoing

7. **Audit every PR** for accidental exposure of numeric constants, thresholds, or ML parameters in the public repo.
8. **CI check**: Add a pre-commit hook or CI step that scans for patterns resembling scoring constants (floating-point literals assigned to UPPER_CASE variables) in `src/security/ml/` and `src/microkernel/`.

---

> **Next Review**: Q1 2027
> **Review Cadence**: Quarterly
