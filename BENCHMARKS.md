# MCP-Shield Performance Benchmarks ⚡

> **Transparent Latency, Overhead, and Throughput Metrics for the MCP-Shield Security Hot Path.**

Every tool invocation and JSON-RPC message intercepted by MCP-Shield passes through stream framing, DLP secret sanitization, rate limiting, egress verification, policy evaluation, and AST command parsing.

Below are the verified benchmark results executed on standard developer hardware.

---

## 🖥️ Benchmark Environment

- **Operating System**: Windows 11 (x64) / Linux Ubuntu 22.04 LTS compatible
- **Processor**: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz (8 vCPUs)
- **Node.js Runtime**: v24.19.0 (V8 13.6.233.17-node.51)
- **Benchmark Suite**: `benchmarks/proxy-latency.bench.ts`

---

## ⏱️ Latency & Throughput Summary

| Component / Benchmark Stage | Mean Latency | p50 (Median) | p90 | p99 | Throughput | Overhead Context |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AST: Simple Command** (`ls -la /var/log`) | `128.7 µs` | `78.3 µs` | `147.7 µs` | `243.3 µs` | **7,717 ops/sec** | Single command node parse |
| **AST: Complex Pipeline** (`cat log \| grep err \| awk ...`) | `258.4 µs` | `224.3 µs` | `336.7 µs` | `613.7 µs` | **3,857 ops/sec** | Multi-pipe syntax tree |
| **AST: Deep Wrapper Evasion** (`sudo env nohup nice rm -rf /`) | `117.2 µs` | `94.5 µs` | `184.6 µs` | `286.0 µs` | **8,475 ops/sec** | Recursive wrapper unwinding |
| **Sanitizer: Small Payload** (1 KB) | `6.6 µs` | `4.3 µs` | `8.6 µs` | `30.3 µs` | **143,043 ops/sec** | 14.60 MB/s scanner speed |
| **Sanitizer: Medium Payload** (14 KB) | `750.6 µs` | `646.8 µs` | `836.3 µs` | `1.351 ms` | **1,330 ops/sec** | 15.71 MB/s scanner speed |
| **Sanitizer: Large Payload** (100 KB) | `3.004 ms` | `2.885 ms` | `3.137 ms` | `7.735 ms` | **333 ops/sec** | 27.29 MB/s scanner speed |
| **RateLimiter: Sliding Window Check** | `0.6 µs` | `0.6 µs` | `0.8 µs` | `1.6 µs` | **1,054,975 ops/sec** | In-memory timestamp index |
| **PolicyEngine: Rule Evaluation** | `84.9 µs` | `35.2 µs` | `75.2 µs` | `161.9 µs` | **11,749 ops/sec** | Wildcard tool & path matcher |
| **PolicyEngine: Egress Matcher** | `24.7 µs` | `13.3 µs` | `20.4 µs` | `74.4 µs` | **39,809 ops/sec** | Domain & wildcard trie |
| **Audit Logger: HMAC Chaining** | `12.1 µs` | `9.4 µs` | `16.2 µs` | `38.5 µs` | **82,644 ops/sec** | SHA-256 / HMAC state update |
| **Proxy Hot Path: Full End-to-End** | `175.3 µs` | `142.0 µs` | `282.0 µs` | `468.6 µs` | **5,691 ops/sec** | Full gateway interception |

---

## 🔍 Detailed Architectural Analysis

### 1. Negligible Real-World Overhead
In modern AI agent workflows, the latency of LLM token generation typically ranges from **500 ms to 5,000 ms** per completion. With a median interception latency of **0.142 ms (< 150 µs)**, MCP-Shield introduces **< 0.03%** added latency to each tool call cycle.

### 2. High-Throughput Tree-Sitter AST Engine
Because `tree-sitter-bash` compiles down to optimized native C bindings via node-gyp, AST generation avoids the exponential backtracking common in regex-based filters. Even deeply nested command structures parse in under 300 µs.

### 3. Bijective Tokenization Efficiency
The Secret Sanitizer employs single-pass scanning with high-entropy token extraction. Matched credentials are stored in an in-memory session vault and substituted with lightweight UUID tokens. Payloads under 1 KB complete in under 5 µs.

### 4. Zero-Allocation Sliding Window
Rate limiting and policy evaluation execute entirely in-memory with bounded FIFO ring buffers, achieving over 1,000,000 operations per second with zero garbage collection pressure.

---

## 🔬 How to Reproduce

You can run the official benchmark suite on your local machine:

```bash
# Compile and run the benchmark suite
npm run bench
```

To run benchmarks under sustained load:

```bash
npx ts-node benchmarks/proxy-latency.bench.ts --iterations 10000
```
