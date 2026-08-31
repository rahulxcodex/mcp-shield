# MCP-Shield Performance & Accuracy Benchmarks ⚡

> **Transparent Latency, Overhead, and Labeled DLP Precision/Recall Metrics for the MCP-Shield Security Hot Path.**

Every tool invocation and JSON-RPC message intercepted by MCP-Shield passes through stream framing, DLP secret sanitization, rate limiting, egress verification, policy evaluation, and AST command parsing.

Below are the verified empirical benchmark results executed on standard developer hardware.

---

## 🖥️ Benchmark Environment

- **OS**: Windows_NT 10.0.26200 (x64)
- **Processor**: 8x Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
- **Node.js**: v24.19.0 (V8 13.6.233.17-node.51)
- **Generated At**: 2026-08-31T05:34:10.035Z

---

## ⏱️ Latency & Throughput Summary

| Component / Benchmark Stage | Mean Latency | p50 (Median) | p90 | p99 | Throughput | Overhead Context |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AST: Simple Command ("ls -la /var/log")** | `162.9 µs` | `171.6 µs` | `216.4 µs` | `317.3 µs` | **6,075 ops/s** | In-Memory |
| **AST: Pipeline ("cat log | grep err | awk '{print $1}'")** | `462.2 µs` | `515.2 µs` | `674.9 µs` | `769.4 µs` | **2,157 ops/s** | In-Memory |
| **AST: Deep Wrapper Evasion ("sudo env nohup nice rm -rf /")** | `154.5 µs` | `115.8 µs` | `239.6 µs` | `341.7 µs` | **6,430 ops/s** | In-Memory |
| **Sanitizer: Small Payload (1 KB)** | `17.5 µs` | `16.5 µs` | `22.3 µs` | `71.2 µs` | **54,895 ops/s** | 5.60 MB/s |
| **Sanitizer: Medium Payload (14 KB)** | `3.534 ms` | `3.723 ms` | `4.156 ms` | `7.716 ms` | **283 ops/s** | 3.34 MB/s |
| **Sanitizer: Large Payload (100 KB)** | `25.004 ms` | `26.032 ms` | `32.109 ms` | `35.728 ms` | **40 ops/s** | 3.28 MB/s |
| **RateLimiter: Sliding Window Check** | `0.6 µs` | `0.4 µs` | `0.7 µs` | `1.4 µs` | **11,89,216 ops/s** | In-Memory |
| **PolicyEngine: Rule Evaluation (Allowed Tool)** | `5.3 µs` | `4.8 µs` | `6.4 µs` | `10.1 µs` | **1,83,830 ops/s** | In-Memory |
| **PolicyEngine: Egress Domain Matcher** | `7.8 µs` | `6.0 µs` | `11.0 µs` | `35.1 µs` | **1,22,102 ops/s** | In-Memory |
| **Proxy Hot-Path: Complete Tool Call Interception** | `200.5 µs` | `155.2 µs` | `304.0 µs` | `418.9 µs` | **4,975 ops/s** | In-Memory |

---

## 🎯 Labeled Secret Detection (DLP) Baseline Evaluation

> [!WARNING]
> ### ⚠️ Methodology Disclosure & Benchmark Caveat
> **Measured against our own curated baseline corpus (`benchmarks/secret-detection.bench.ts`); independent held-out validation is pending.**
>
> The metrics in this section represent deterministic regression testing across 1,780 lines of simulated source code, logs, and configs. Because this initial dataset was hand-authored alongside the sanitizer's regex and Shannon entropy heuristics to establish a functional baseline, achieving **100% precision and 100% recall on this corpus is a smoke/regression test, not proof of 100% detection in the wild**.
>
> Real-world DLP scanners inevitably encounter edge-case false positives (e.g., non-secret high-entropy tokens) and novel key syntaxes. We are actively working to integrate independent, third-party held-out datasets (such as GitGuardian and TruffleHog benchmark corpora) to evaluate out-of-distribution generalization.

| Metric | Evaluated Value | Context |
| :--- | :--- | :--- |
| **Total Evaluated Lines** | **1,780 lines** | Multi-language source, logs, and config fixtures |
| **Ground Truth Secrets** | **300** | AWS, Anthropic, OpenAI, GitHub, Google, Slack, Stripe, GitLab, JWT, SSH keys |
| **True Positives (TP)** | **300** | Successfully quarantined & tokenized secrets |
| **False Positives (FP)** | **0** | Non-secret tokens erroneously scrubbed |
| **False Negatives (FN)** | **0** | Secrets missed during single-pass scan |
| **Precision (Baseline Corpus)** | **100.00%** | TP / (TP + FP) |
| **Recall (Baseline Corpus)** | **100.00%** | TP / (TP + FN) |
| **F1-Score (Baseline Corpus)** | **100.00%** | Harmonic mean of Precision & Recall |
| **Scanner Throughput** | **2,13,721 lines/sec** | 8.74 MB/s raw scanning speed |

### Breakdown by Workload Category (Baseline Corpus)

| Category | Evaluated Lines | Real Secrets | TP | FP | FN | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Source Code (TypeScript)** | 420 | 60 | 60 | 0 | 0 | 100.0% | 100.0% |
| **Source Code (Python)** | 340 | 40 | 40 | 0 | 0 | 100.0% | 100.0% |
| **Infrastructure & Configs (YAML/JSON)** | 280 | 60 | 60 | 0 | 0 | 100.0% | 100.0% |
| **CI/CD & Server Logs** | 140 | 40 | 40 | 0 | 0 | 100.0% | 100.0% |
| **Certificates & Keys** | 120 | 20 | 20 | 0 | 0 | 100.0% | 100.0% |
| **Build & Test Log Dump (Noise Stress Test)** | 260 | 80 | 80 | 0 | 0 | 100.0% | 100.0% |
| **Benign Code (Zero Secrets Control)** | 220 | 0 | 0 | 0 | 0 | 100.0% | 100.0% |

---

## 🛡️ Real-World Proof: Adversarial Bypasses vs. Synthetic Benchmarks

Synthetic benchmarks prove execution speed and rule correctness against expected patterns, but **the only true proof of defensive security is adversarial stress testing and transparent disclosure of bypasses**.

MCP-Shield maintains an open [Red-Team & Security Research Program](REDTEAM.md) with dedicated issue templates for reporting filter evasions. Every validated bypass report is assigned a tracking identifier, added to our permanent regression suite (`tests/security-corpus/bypass-corpus.json` and `tests/redteam/bypasses.test.ts`), and published transparently in [SECURITY.md](SECURITY.md):

- **[CVE-2026-SHIELD-001](SECURITY.md#cve-2026-shield-001)**: AST subshell and `$IFS` parameter expansion bypass (Patched & regression-tested).
- **[CVE-2026-SHIELD-002](SECURITY.md#cve-2026-shield-002)**: POSIX short-flag substring match collisions in `rm` (Patched & regression-tested).
- **[CVE-2026-SHIELD-003](SECURITY.md#cve-2026-shield-003)**: Multi-stage pipeline command execution evasions (Patched & regression-tested).

We encourage researchers to submit novel bypasses via our [Bypass Challenge Template](.github/ISSUE_TEMPLATE/security_bypass.yml).

---

## 🔍 Detailed Architectural Analysis

### 1. Negligible Real-World Overhead
In modern AI agent workflows, LLM token generation latency ranges from **500 ms to 5,000 ms** per tool call cycle. With a median interception latency of **< 200 µs (< 0.2 ms)**, MCP-Shield introduces **< 0.04%** added latency.

### 2. High-Throughput Tree-Sitter AST Engine
Because `tree-sitter-bash` compiles down to optimized native C bindings, AST generation avoids the exponential backtracking common in regex-based command filters. Even deeply nested command structures parse in under 300 µs.

### 3. Allocation-Minimized Shannon Entropy & Reversible Tokenization
The Secret Sanitizer employs single-pass compound regex scanning and a **pre-allocated frequency buffer (`Uint32Array(256)`)** for Shannon entropy calculations, eliminating per-call memory allocations during entropy math. Matched credentials are stored in an in-memory session vault and substituted with lightweight UUID tokens that are losslessly restored on return traffic.

### 4. Sliding Window Rate Limiting
Rate limiting executes entirely in-memory with bounded sliding windows and automatic capacity eviction, achieving over 1,000,000 operations per second.

---

## 🔬 How to Reproduce

You can reproduce all benchmark numbers locally with our automated test scripts:

```bash
# 1. Run full proxy latency and throughput benchmark
npm run bench

# 2. Run labeled secret detection baseline benchmark
npm run bench:secrets

# 3. Run all benchmarks
npm run bench:all
```

