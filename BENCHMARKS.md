# MCP-Shield Performance & Accuracy Benchmarks ⚡

> **Transparent Latency, Overhead, and Labeled DLP Precision/Recall Metrics for the MCP-Shield Security Hot Path.**

Every tool invocation and JSON-RPC message intercepted by MCP-Shield passes through stream framing, DLP secret sanitization, rate limiting, egress verification, policy evaluation, and AST command parsing.

Below are the verified empirical benchmark results executed on standard developer hardware.

---

## 🖥️ Benchmark Environment

- **OS**: Windows_NT 10.0.26200 (x64)
- **Processor**: 8x Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
- **Node.js**: v24.19.0 (V8 13.6.233.17-node.51)
- **Generated At**: 2026-09-01T17:52:43.914Z

---

## ⏱️ Latency & Throughput Summary

| Component / Benchmark Stage | Mean Latency | p50 (Median) | p90 | p99 | Throughput | Overhead Context |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AST: Simple Command ("ls -la /var/log")** | `90.6 µs` | `81.7 µs` | `117.2 µs` | `216.4 µs` | **10,949 ops/s** | In-Memory |
| **AST: Pipeline ("cat log | grep err | awk '{print $1}'")** | `298.7 µs` | `264.4 µs` | `340.8 µs` | `603.6 µs` | **3,339 ops/s** | In-Memory |
| **AST: Deep Wrapper Evasion ("sudo env nohup nice rm -rf /")** | `90.7 µs` | `83.0 µs` | `114.2 µs` | `203.3 µs` | **10,969 ops/s** | In-Memory |
| **Sanitizer: Small Payload (1 KB)** | `51.7 µs` | `57.6 µs` | `61.5 µs` | `131.6 µs` | **19,219 ops/s** | 1.96 MB/s |
| **Sanitizer: Medium Payload (14 KB)** | `14.991 ms` | `14.898 ms` | `16.624 ms` | `21.142 ms` | **67 ops/s** | 0.79 MB/s |
| **Sanitizer: Large Payload (100 KB)** | `125.316 ms` | `124.491 ms` | `134.261 ms` | `157.091 ms` | **8 ops/s** | 0.65 MB/s |
| **RateLimiter: Sliding Window Check** | `0.3 µs` | `0.3 µs` | `0.4 µs` | `0.8 µs` | **21,25,489 ops/s** | In-Memory |
| **PolicyEngine: Rule Evaluation (Allowed Tool)** | `1.1 µs` | `0.8 µs` | `1.7 µs` | `2.2 µs` | **8,43,953 ops/s** | In-Memory |
| **PolicyEngine: Egress Domain Matcher** | `7.5 µs` | `6.4 µs` | `11.0 µs` | `24.2 µs` | **1,30,096 ops/s** | In-Memory |
| **Proxy Hot-Path: Complete Tool Call Interception** | `189.6 µs` | `181.4 µs` | `202.2 µs` | `266.7 µs` | **5,266 ops/s** | In-Memory |

---

## 🎯 Labeled Secret Detection (DLP) Precision & Recall

To ground detection claims with empirical evidence, the Secret Sanitizer is evaluated against a curated, multi-language dataset of realistic source files (TypeScript, Python, YAML, JSON, Shell, SQL), build logs, CI environment dumps, and stack traces with both true credential patterns and high-entropy non-secret noise (SHA-256 hashes, UUIDs, CSS hashes, base64 payloads).

| Metric | Evaluated Value | Context |
| :--- | :--- | :--- |
| **Total Evaluated Lines** | **1,780 lines** | Multi-language source, logs, and config fixtures |
| **Ground Truth Secrets** | **300** | AWS, Anthropic, OpenAI, GitHub, Google, Slack, Stripe, GitLab, JWT, SSH keys |
| **True Positives (TP)** | **300** | Successfully quarantined & tokenized secrets |
| **False Positives (FP)** | **0** | Non-secret tokens erroneously scrubbed |
| **False Negatives (FN)** | **0** | Secrets missed during single-pass scan |
| **Precision** | **100.00%** | TP / (TP + FP) |
| **Recall** | **100.00%** | TP / (TP + FN) |
| **F1-Score** | **100.00%** | Harmonic mean of Precision & Recall |
| **Scanner Throughput** | **87,307 lines/sec** | 3.57 MB/s raw scanning speed |

### Breakdown by Workload Category

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

## 🔍 Detailed Architectural Analysis

### 1. Negligible Real-World Overhead
In modern AI agent workflows, LLM token generation latency ranges from **500 ms to 5,000 ms** per tool call cycle. With a median interception latency of **< 200 µs (< 0.2 ms)**, MCP-Shield introduces **< 0.04%** added latency.

### 2. High-Throughput Tree-Sitter AST Engine
Because `tree-sitter-bash` compiles down to optimized native C bindings, AST generation avoids the exponential backtracking common in regex-based command filters. Even deeply nested command structures parse in under 300 µs.

### 3. Allocation-Minimized Shannon Entropy & Reversible Tokenization
The Secret Sanitizer employs single-pass compound regex scanning and a pre-allocated frequency buffer for Shannon entropy calculations, eliminating per-call memory allocations. Matched credentials are stored in an in-memory session vault and substituted with lightweight UUID tokens that are provably losslessly restored on return traffic.

### 4. Sliding Window Rate Limiting
Rate limiting executes entirely in-memory with bounded sliding windows and automatic capacity eviction, achieving over 1,000,000 operations per second.

---

## 🔬 How to Reproduce

You can reproduce all benchmark numbers locally with our automated test scripts:

```bash
# 1. Run full proxy latency and throughput benchmark
npm run bench

# 2. Run labeled secret detection precision & recall benchmark
npm run bench:secrets

# 3. Run all benchmarks
npm run bench:all
```
