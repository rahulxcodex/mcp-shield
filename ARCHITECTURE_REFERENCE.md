# MCP-Shield Architecture & Codebase Reference

> **Complete module catalog, public algorithm descriptions, and function reference for the MCP-Shield Zero-Trust Security Gateway.**

This document provides transparency into the engineering foundations of MCP-Shield. It covers the public algorithms, data structures, and design patterns used across the codebase — enabling users, security researchers, and contributors to understand, audit, and trust the system.

> **Trade Secret Notice**: MCP-Shield's proprietary risk scoring weights, attack corpus, behavioral kill chains, and ML model training data reside exclusively in private repositories and are not documented here. This document covers only the open-source public gateway. See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for the multi-repository boundary specification.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Module Reference](#2-module-reference)
3. [Public Algorithm Descriptions](#3-public-algorithm-descriptions)
4. [Data Flow & Pipeline Architecture](#4-data-flow--pipeline-architecture)
5. [Configuration & Policy System](#5-configuration--policy-system)
6. [CLI Command Reference](#6-cli-command-reference)
7. [Testing Architecture](#7-testing-architecture)

---

## 1. System Overview

MCP-Shield is a zero-trust inline security gateway that intercepts JSON-RPC streams between AI host applications (Claude Desktop, Cursor, Windsurf, Cline, Antigravity) and downstream MCP servers. It enforces a defense-in-depth pipeline comprising AST-level command analysis, data loss prevention, network egress control, cryptographic audit trails, and sandboxed execution.

### Architecture Principles

| Principle | Implementation |
| :--- | :--- |
| **Deny-by-Default** | Unknown tools blocked (`UNKNOWN_TOOL_BLOCKED`), private networks blocked, env vars stripped |
| **Schema-First** | Tool capabilities inferred from JSON Schema parameter definitions, not names |
| **AST over Regex** | Shell commands parsed into Concrete Syntax Trees via native `tree-sitter` bindings |
| **Bijective DLP** | Secrets tokenized with reversible session tokens; restored only for trusted tools |
| **Fail-Closed** | Any pipeline exception defaults to `BLOCK` or `QUARANTINE` |
| **Tamper-Evident** | Every decision chained via HMAC-SHA-256 with monotonic sequence numbers |

### Technology Stack

- **Runtime**: Node.js 20.x / 22.x (TypeScript 5.x)
- **Native Bindings**: `tree-sitter`, `tree-sitter-bash` (C/C++ via N-API)
- **Cryptography**: Node.js `crypto` module (AES-256-GCM, HMAC-SHA-256, Ed25519, SHA-256)
- **Web Dashboard**: Next.js 16 with React 19, Tailwind CSS, Recharts
- **CI/CD**: GitHub Actions with OIDC npm publishing, CycloneDX SBOM
- **Test Framework**: Jest with `fast-check` property-based testing

---

## 2. Module Reference

### `src/core/` — Gateway Core

The core module implements the JSON-RPC stream proxy, message dispatching, session management, and the security pipeline orchestration.

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `proxy.ts` | `ProxyServer` | Main gateway server — spawns child MCP server processes, intercepts stdio streams, manages lifecycle |
| `stream-framing.ts` | `JsonRpcStreamFramer` | Chunk defragmentation for stdio JSON-RPC streams with 10MB DoS bounds and UTF-8 alignment |
| `protocol-validator.ts` | `ProtocolValidator` | Validates JSON-RPC 2.0 message structure, enforces nesting depth limits (32), schema compliance |
| `dispatcher.ts` | `RequestDispatcher` | Routes validated messages through the security pipeline phases |
| `session.ts` | `SessionManager` | Per-session state tracking, tool registry, capability manifest caching |
| `mcp-protocol-state-machine.ts` | `MCPProtocolStateMachine` | Finite state machine enforcing MCP lifecycle transitions (initialize, initialized, shutdown) |
| `ai-runtime-security.ts` | `AIRuntimeSecurityManager` | Coordinates runtime security checks across all subsystems |

#### `src/core/guards/` — Pipeline Guards

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `ingress-guard.ts` | `IngressGuard` | First-stage validation: rate limiting, honey token detection, schema validation |
| `tool-guard.ts` | `ToolGuard` | Second-stage: AST analysis, capability enforcement, path traversal detection, egress policy |
| `output-guard.ts` | `OutputGuard` | Third-stage: output-side DLP scanning, amplification bounds, secret marker detection |

#### `src/core/broker/` — Execution Broker

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `execution-broker.ts` | `ExecutionBroker` | Capability-enforced tool execution with cryptographic manifest verification and secret restoration |

#### `src/core/pipeline/` — Security Pipeline

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `security-pipeline.ts` | `SecurityPipeline` | Orchestrates the 5-phase policy engine hierarchy (Critical Detectors → Schema Capability → Tool Rules → Risk Escalation → Fail-Closed) |

#### `src/core/lifecycle/` — Lifecycle Management

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `lifecycle-manager.ts` | `LifecycleManager` | Manages child process spawning, crash recovery, graceful shutdown, and exit code propagation |

#### `src/core/runtime/` — Security Runtime

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `security-runtime.ts` | `SecurityRuntime` | Unified runtime orchestrating all security subsystems with hot-reload configuration |

---

### `src/security/` — Security Engines

The security module contains all detection, analysis, and enforcement engines.

#### AST Analysis (Shell Firewalls)

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `ast-analyzer.ts` | `ASTAnalyzer` | POSIX shell analysis via `tree-sitter-bash` — wrapper unwinding, flag disambiguation, subshell detection, dangerous primitive blocking |
| `powershell-analyzer.ts` | `PowerShellASTAnalyzer` | PowerShell semantic parser — cmdlet alias canonicalization, `-EncodedCommand` recursive base64 unrolling, `$env:*` leakage, dynamic `.NET` reflection |
| `cmd-analyzer.ts` | `CmdAnalyzer` | Windows cmd.exe parser — caret de-obfuscation, compound operator chaining, delayed expansion, `vssadmin`/`bcdedit` system tampering detection |

#### Data Loss Prevention (DLP)

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `sanitizer.ts` | `SecretSanitizer` | Bijective format-preserving secret tokenization with Shannon entropy detection and pre-allocated frequency buffers |
| `vault.ts` | `SecretVault` | AES-256-GCM ephemeral vault for session-scoped secret storage and granular trust-based restoration |

#### `src/security/dlp/` — Streaming DLP

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `incremental-secret-scanner.ts` | `IncrementalSecretScanner` | Streaming O(1) memory secret detection using prefix trie pre-filtering and sliding overlap windows |

#### Policy & Network

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `policy-engine.ts` | `PolicyEngine` | YAML-driven declarative policy evaluation with path glob matching and domain wildcard rules |
| `capabilities.ts` | `CapabilityManifest` | Schema-first capability inference from JSON Schema parameter names and formats |
| `network-proxy.ts` | `EgressNetworkShield` | Multi-IP DNS rebinding defense, IPv4/IPv6 CIDR evaluation via BigInt, socket-level IP pinning |
| `ip-utils.ts` | `IPClassifier` | IPv4/IPv6 address parsing, CIDR matching, link-local/metadata/private range classification |
| `rate-limiter.ts` | `SlidingWindowRateLimiter` | Per-tool sliding-window rate limiting with O(1) LRU capacity eviction |
| `path-resolver.ts` | `PathResolver` | Canonical path resolution with symlink rejection and traversal normalization |
| `authorization.ts` | `AuthorizationEngine` | Tool-level authorization policy enforcement |
| `circuit-breaker.ts` | `CircuitBreaker` | Fault-tolerant circuit breaker for external service dependencies |
| `canary.ts` | `CanaryHoneytokenManager` | Synthetic honeypot tool injection and tripwire detection |
| `config.ts` | `SecurityConfig` | Security configuration validation and defaults |
| `canonical-json.ts` | `CanonicalJSON` | RFC 8785 canonical JSON serialization for deterministic hash digests |

#### `src/security/ir/` — Intermediate Representation

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `command-ir.ts` | `SecurityCommandIR` | Normalized intermediate representation unifying bash, PowerShell, and cmd.exe ASTs into a common analysis format |

#### `src/security/ml/` — Machine Learning Models

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `tabular-risk-model.ts` | `TabularRiskModel` | Feature-engineered risk scoring model using versioned feature vectors |
| `text-security-classifier.ts` | `TextSecurityClassifier` | Text-based security intent classification for tool descriptions and parameters |
| `behavior-anomaly-detector.ts` | `BehaviorAnomalyDetector` | Session-level behavioral anomaly detection via Markov chain transition analysis |
| `schema-drift-detector.ts` | `SchemaDriftDetector` | Continuous tool schema fingerprint monitoring for post-initialization drift |
| `novelty-scorer.ts` | `NoveltyScorer` | Out-of-distribution detection for previously unseen tool invocation patterns |
| `adversarial-learning-loop.ts` | `AdversarialLearningLoop` | Continuous model improvement from community red-team bypass submissions |
| `model-governance-registry.ts` | `ModelGovernanceRegistry` | ML model lifecycle management (shadow → canary → production promotion) |
| `privacy-telemetry.ts` | `PrivacyTelemetry` | Privacy-preserving telemetry with differential privacy guarantees |

#### `src/security/graph/` — Security Graph Analysis

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `security-graph.ts` | `SecurityGraph` | Weighted directed graph of tool-to-resource relationships for attack surface analysis |
| `environment-scanner.ts` | `EnvironmentScanner` | Host environment capability discovery and threat surface mapping |

#### `src/security/blast-radius/` — Impact Analysis

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `blast-radius-engine.ts` | `BlastRadiusEngine` | Multi-vector blast radius computation for worst-case impact assessment |

#### `src/security/dataflow/` — Taint Tracking

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `toxic-flow-engine.ts` | `ToxicFlowEngine` | Cross-tool taint propagation tracking from sources through transforms to sinks |

#### `src/security/intelligence/` — Signal Fusion

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `intelligence-bus.ts` | `IntelligenceBus` | Typed security signal aggregation with deterministic fusion and hard-block precedence |

#### `src/security/adversarial/` — Adversarial Testing

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `adversarial-generator.ts` | `AdversarialGenerator` | Automated mutation-based adversarial test case generation for parser hardening |

#### `src/security/attack-path/` — Attack Path Discovery

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `customer-fuzzer.ts` | `CustomerFuzzer` | Customer-specific attack path discovery and policy stress testing |

#### `src/security/provenance/` — Supply Chain

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `provenance-manager.ts` | `ProvenanceManager` | Package identity verification, binary digest tracking, incident history |

#### `src/security/supply-chain/` — Dependency Security

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| Various | CVE scanner, typo-squat detector, SBOM validator | Automated dependency security analysis and supply chain risk assessment |

#### `src/security/authz/` — Authorization Service

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `authorization-service.ts` | `AuthorizationService` | Fine-grained authorization policy evaluation with role-based access control |

#### `src/security/audit/` — Audit Infrastructure

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `audit-ledger.ts` | `AuditLedger` | Cryptographic audit ledger with hash chain integrity verification |
| `sqlite-audit-sink.ts` | `SqliteAuditSink` | Persistent audit storage with SQLite for offline analysis |

#### `src/security/airgap/` — Air-Gap Security

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `schema-pinning.ts` | `SchemaPinning` | Deterministic schema fingerprinting for offline integrity verification |

#### `src/security/budget/` — Resource Bounding

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `security-budget.ts` | `SecurityBudget` | Execution resource budgets preventing runaway analysis cost |

#### `src/security/response/` — Output Security

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `response-pipeline.ts` | `ResponseSecurityPipeline` | Output-side security inspection pipeline |

#### `src/security/kernel/` — Protocol Kernel

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `agent-security-kernel.ts` | `AgentSecurityKernel` | Pluggable protocol adapter kernel supporting multiple agent communication protocols |

---

### `src/sandbox/` — Isolation Boundaries

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `cow-fs.ts` | `CopyOnWriteFS` | File mutation interception with overlay staging, unified diff generation, TOCTOU defense (canonical path + lstat + mutex), atomic commit |
| `container-sandbox.ts` | `ContainerSandbox` | Docker/OCI container isolation with `--cap-drop=ALL`, `--network=none`, `--read-only`, CPU/PID limits |

---

### `src/audit/` — Cryptographic Audit Trail

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `session-logger.ts` | `SessionLogger` | Append-only JSONL logging with HMAC-SHA-256 hash chain, Merkle root computation, monotonic sequence numbers |

---

### `src/scanner/` — Ecosystem Scanner

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `agent-ecosystem-scanner.ts` | `AgentEcosystemScanner` | Auto-discovers and audits 9 AI agent environments (Claude Desktop, Cursor, Windsurf, Cline, Antigravity, Continue, Zed, Custom SDK, VS Code) |

---

### `src/cloud/` — Cloud Telemetry

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `telemetry.ts` | `CloudTelemetryEmitter` | HMAC-authenticated telemetry streaming to cloud console |
| `state/distributed-state-adapter.ts` | `DistributedStateAdapter` | Multi-tenant state synchronization via Supabase |

---

### `src/dashboard/` — Live Dashboard

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `server.ts` | `DashboardServer` | Express + WebSocket server providing real-time telemetry on `localhost:3333` |

---

### `src/microkernel/` — High-Performance Engine

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `wasm-loader.ts` | `WASMPluginLoader` | WebAssembly module loader for native-speed security plugins |
| `ring-buffer/lmax-disruptor.ts` | `LMAXDisruptor` | Lock-free ring buffer for high-throughput event processing |
| `fastpath/tier1-micro-kernel.ts` | `Tier1MicroKernel` | Ultra-low-latency fast-path for common security decisions |
| `fastpath/timing-shield.ts` | `TimingShield` | Constant-time comparison utilities for timing attack prevention |
| `fastpath/simdjson-tokenizer.ts` | `SimdJsonTokenizer` | SIMD-optimized JSON tokenization for high-throughput parsing |
| `fastpath/pthash.ts` | `PTHash` | Perfect hash function for O(1) tool identity lookups |
| `fastpath/groupsort-dscnn.ts` | `GroupSortDSCNN` | Optimized sorting and classification for security signal processing |

---

### `src/cli/` — Command Line Interface

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `commands/protect.ts` | `ProtectCommand` | Auto-discover and patch Claude/Cursor/Cline/Windsurf configurations |
| `commands/scan.ts` | `ScanCommand` | Audit installed MCP configurations for CVEs and plaintext secrets |
| `commands/link.ts` | `LinkCommand` | Pair local CLI with cloud console via API key |
| `commands/replay.ts` | `ReplayCommand` | Replay and analyze historical audit trail sessions |
| `commands/replay-eval.ts` | `ReplayEvalCommand` | Evaluate replay sessions against updated policies |
| `commands/stats.ts` | `StatsCommand` | Display local interception counts and security metrics |

---

### `src/adapters/` — Protocol Adapters

Protocol adapters enable MCP-Shield to protect multiple agent communication protocols beyond standard MCP stdio.

---

### `src/tui/` — Terminal UI

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `prompt-bridge.ts` | `PromptBridge` | Interactive terminal prompt for just-in-time human approval of sandboxed operations |

---

### `src/config/` — Configuration

Default policy configuration files and plan definitions for security profiles.

---

### `src/watermark/` — Watermarking

Cryptographic watermarking infrastructure for canary tripwire tokens and output provenance tracking.

---

### `src/benchmarks/` — Benchmark Harness

| File | Exported Symbol | Purpose |
| :--- | :--- | :--- |
| `mcp-security-benchmark.ts` | `MCPSecurityBenchmark` | Standardized benchmark runner for latency, throughput, and accuracy measurements |

---

## 3. Public Algorithm Descriptions

The following algorithms are implemented in the open-source gateway. Their design is publicly documented to build trust and enable independent security auditing.

### 3.1 Tree-Sitter AST Shell Parsing

**Purpose**: Eliminate shell command obfuscation that defeats regex-based security filters.

**Approach**: Commands are compiled into Concrete Syntax Trees (CSTs) via native `tree-sitter-bash` C bindings. The CST is traversed to:
1. Recursively unwrap execution wrappers (`sudo`, `env`, `nohup`, `nice`, `stdbuf`, `timeout`, `su`, `doas`, `pkexec`, `cmd /c`, `powershell -Command`)
2. Split combined short flags (`-rf` → `-r`, `-f`) using POSIX-standard flag disambiguation
3. Resolve compound statements (`;`, `&&`, `||`, `|`) into individual commands
4. Detect dangerous primitives (`rm -rf /`, `mkfs.*`, `dd if=/dev/...`, fork bombs)
5. Inspect process substitutions, heredocs, and backtick subshells

**Complexity**: O(n) single-pass tree traversal where n = AST node count. Parser input capped at 64KB to prevent DoS.

### 3.2 Shannon Entropy Secret Detection

**Purpose**: Identify high-entropy credential strings (API keys, tokens, passwords) in tool arguments.

**Approach**: Candidate strings are evaluated using Shannon information entropy:

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

where $p(x_i)$ is the frequency of byte value $x_i$ in the candidate string.

**Optimization**: A single pre-allocated `Uint32Array(256)` frequency buffer is reused across all entropy calculations and zeroed via `.fill(0)` between evaluations, eliminating per-call heap allocation.

**False-Positive Suppression**: UUIDs (`8-4-4-4-12`), pure hex SHA-256/MD5/Git hashes, and minified identifiers are automatically excluded unless accompanied by explicit credential context markers.

### 3.3 Sliding-Window Rate Limiting

**Purpose**: Prevent runaway autonomous tool-calling loops.

**Approach**: Per-tool invocation tracking using a sliding time window. Each tool maintains a deque of timestamps. On each invocation:
1. Evict timestamps older than the window duration
2. Check if count exceeds the per-tool threshold
3. If exceeded, return `RATE_LIMITED` decision

**Capacity Management**: An LRU eviction policy bounds total tracked tool count to prevent memory exhaustion from diverse tool identities.

### 3.4 HMAC-SHA-256 Merkle Audit Chain

**Purpose**: Guarantee tamper-evidence for the session audit trail.

**Construction**:

$$H_0 = \text{GENESIS}$$

$$H_n = \text{HMAC-SHA256}(H_{n-1} \| \text{CanonicalJSON}(\text{Data}_n), K_{\text{audit}})$$

Each log entry includes a monotonic sequence number (`seq: 0, 1, 2, ...`) preventing entry deletion or reordering. The canonical JSON serialization follows RFC 8785 for deterministic byte-level reproducibility.

### 3.5 Multi-IP DNS Rebinding Defense

**Purpose**: Prevent DNS rebinding attacks where an allowed domain resolves to internal IPs.

**Approach**:
1. Resolve all A and AAAA records for the target domain (`dns.lookup(host, { all: true })`)
2. Parse each resolved IP into numerical BigInt representation
3. Evaluate every IP against CIDR subnet deny-lists (loopback, link-local, cloud metadata, private ranges)
4. Normalize IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1` → `127.0.0.1`)
5. If **any** resolved address violates policy, reject the entire request
6. Pin the connection to the verified resolved IP while preserving the original `Host` header

### 3.6 Schema-First Capability Inference

**Purpose**: Categorize tool security capabilities from JSON Schema parameter definitions rather than easily spoofed tool names.

**Mapping**: The following parameter names and formats trigger capability classifications:
- `shellExecution`: `command`, `cmd`, `script`, `bash`, `code`, `exec_command`
- `filesystemWrite`: `content`, `text`, `patch`, `write_path`, `destination`, `overwrite`
- `filesystemRead`: `path`, `file`, `filepath`, `dir`, `directory`, or `format: "path"`
- `networkAccess`: `url`, `uri`, `endpoint`, `domain`, `host`, or `format: "uri"`
- `secretAccess`: `api_key`, `secret`, `token`, `password`, `credential`

### 3.7 Copy-on-Write File Staging

**Purpose**: Prevent unauthorized file mutations by staging changes for human review.

**Mechanism**:
1. Intercept file mutation tool calls (`write_file`, `edit_file`, `patch_file`)
2. Stage modified contents in `.mcp-shield/cow/` overlay directory
3. Generate unified diffs for operator review
4. On approval, perform atomic commit with TOCTOU defense:
   - Canonical path resolution (reject symlinks via `lstat`)
   - File identity verification (inode/size/hash) before commit
   - Exclusive mutex lock during commit window

### 3.8 Bijective Session Tokenization

**Purpose**: Prevent credential leakage to LLM prompt contexts while enabling trusted tool execution.

**Mechanism**:
1. Scan tool arguments for credential patterns (AWS keys, OpenAI `sk-proj-*`, GitHub PATs `ghp_*`, SSH private keys, etc.)
2. Replace each match with a unique session token: `[[SHIELD_SECRET_xxxxxxxx]]`
3. Store original values in an AES-256-GCM encrypted in-memory vault keyed by the session token
4. Restoration policy based on server trust level:
   - `UNTRUSTED`: Tokens never restored
   - `SUSPICIOUS`: Tokens never restored
   - `TRUSTED` with `secretAccess` capability: Tokens restored in-flight

### 3.9 Dijkstra Attack-Path Analysis

**Purpose**: Compute shortest weighted attack paths through the security graph to identify critical remediation points.

**Approach**: The security graph models tool-to-resource relationships as a weighted directed graph. Dijkstra's algorithm (binary min-heap priority queue) finds minimum-cost attack paths. Articulation point / cut-vertex analysis identifies bridge nodes whose remediation would disconnect entire attack subgraphs.

### 3.10 Bayesian Noisy-OR Risk Fusion

**Purpose**: Combine independent risk signals from multiple detectors into a unified risk score.

**Formula**: For independent detector signals $d_1, d_2, \ldots, d_k$ with individual risk probabilities $p_i$:

$$P(\text{risk}) = 1 - \prod_{i=1}^{k}(1 - p_i)$$

This Noisy-OR model ensures that any single high-confidence detection triggers escalation, while multiple weak signals compound naturally.

> **Note**: The specific weights, exponents, and calibration coefficients applied to individual detector outputs are proprietary and reside in the private `mcp-shield-enterprise-intel` repository.

### 3.11 Prefix Trie DLP Pre-Filtering

**Purpose**: Efficiently pre-filter candidate secret strings in streaming mode.

**Approach**: Known credential prefixes (`sk-proj-`, `ghp_`, `AKIA`, `sk-ant-`, `xoxb-`, etc.) are compiled into a prefix trie. Input streams are scanned using sliding overlap windows with O(1) memory consumption, triggering full entropy analysis only on prefix matches.

### 3.12 Taint Propagation Tracking

**Purpose**: Track data flow from sensitive sources through transformations to output sinks across multi-tool chains.

**Mechanism**: Each data element receives a cryptographic taint hash at its source. As data flows through tool transformations, taint tags propagate. The `ToxicFlowEngine` detects when tainted data reaches an unauthorized sink (e.g., network egress or model context).

---

## 4. Data Flow & Pipeline Architecture

### Inbound Request Processing

```
AI Client → JsonRpcStreamFramer → ProtocolValidator → IngressGuard → ToolGuard → ExecutionBroker
                                                          ↓                ↓            ↓
                                                    RateLimiter     ASTAnalyzer    SecretVault
                                                    CanaryDetector  PolicyEngine   Restoration
                                                    SchemaValidator EgressShield
```

### Outbound Response Processing

```
MCP Server → OutputGuard → SecretSanitizer → SessionLogger → AI Client
                  ↓              ↓                ↓
            AmplificationCheck  DLPScanner     HMACChain
            SecretMarkerScan    EntropyCheck   MerkleRoot
```

### 5-Phase Policy Engine Hierarchy

| Phase | Name | Components | Decision |
| :--- | :--- | :--- | :--- |
| 1 | Critical Detectors | Honey tokens, rate limiter, AST firewall, SSRF | `BLOCK` / `QUARANTINE` |
| 2 | Schema Capability | Capability manifest, attestation validation | `ALLOW` with restrictions |
| 3 | Tool-Specific Rules | Path matchers, domain wildcards, argument validators | `ALLOW` / `BLOCK` |
| 4 | Risk Escalation | Suspicious attestation, risk scoring, behavioral anomaly | `SANDBOX` |
| 5 | Default Fallback | Fail-closed | `BLOCK` |

---

## 5. Configuration & Policy System

MCP-Shield uses a YAML-based declarative policy configuration (`shield.config.default.yaml`) supporting:

- **Tool allowlists/blocklists**: Per-tool capability and argument constraints
- **Path policies**: Glob-based filesystem access control
- **Egress policies**: Domain wildcards and CIDR deny-lists
- **Rate limits**: Per-tool invocation thresholds and window durations
- **Trust profiles**: Server trust levels (`TRUSTED`, `SUSPICIOUS`, `UNTRUSTED`)
- **Sandbox modes**: COW staging vs. Docker container isolation

---

## 6. CLI Command Reference

| Command | Description |
| :--- | :--- |
| `mcp-shield protect` | Auto-discover and patch Claude, Cursor, Cline, and Windsurf configurations |
| `mcp-shield wrap -- <cmd> [args]` | Run any MCP server inside the zero-trust security gateway |
| `mcp-shield scan` | Audit installed MCP configs for CVEs and plaintext secrets |
| `mcp-shield license <key>` | Install enterprise license credential |
| `mcp-shield link --key <key>` | Pair local CLI with cloud console |
| `mcp-shield replay <session>` | Replay and analyze audit trail sessions |
| `mcp-shield stats` | Display local interception metrics |
| `mcp-shield demo` | Interactive sandbox for testing AST and DLP attacks |

---

## 7. Testing Architecture

MCP-Shield maintains **117 test suites** with **1,141 tests** achieving 100% pass rate across Ubuntu and Windows CI matrices (Node.js 20.x, 22.x).

### Test Categories

| Category | Location | Purpose |
| :--- | :--- | :--- |
| Unit Tests | `tests/unit/` | Individual module validation |
| Integration Tests | `tests/integration/` | End-to-end stream framing and proxy |
| Red-Team Tests | `tests/redteam/` | Adversarial bypass regression |
| Security Corpus | `tests/security-corpus/` | Cross-platform attack vector validation |
| Property-Based | `tests/security-corpus/property-based.test.ts` | Randomized permutation fuzzing via `fast-check` |
| Benchmarks | `benchmarks/` | Latency, throughput, and accuracy measurement |

### Running Tests

```bash
# Full suite
npm test

# Red-team challenges
npm run test:redteam

# Property-based fuzzing
npm run fuzz

# Security benchmarks
npm run bench:all
```

---

*MCP-Shield v1.0.25 • [GitHub](https://github.com/rahulxcodex/mcp-shield) • [MIT License](LICENSE)*
