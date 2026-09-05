# MCP Shield — Production Readiness Contract & Specifications

## 1. Executive Summary & Production Charter

MCP Shield is the Zero-Trust Capability Execution Broker, AST Firewall, and Bijective DLP Sanitizer for the Model Context Protocol (MCP) and Autonomous AI Agents. This document establishes the formal engineering, security, reliability, operational, and architectural invariants required for production deployment across all three components of the ecosystem:
1. **MCP Shield Core Engine & Public Gateway** (`rahulxcodex/mcp-shield`, npm `mcpshld`)
2. **Enterprise Threat Intelligence Service** (`rahulxcodex/mcp-shield-enterprise-intel`)
3. **Licensing & Control Plane** (`rahulxcodex/mcp-shield-licensing`)

Production certification requires satisfying verifiable technical controls validated through automated tests, static checks, and cryptographic evidence.

---

## 2. Supported Platforms & Environments

| Component | Supported Runtime / Version | Minimum Requirements | Recommended Production Environment |
| :--- | :--- | :--- | :--- |
| **MCP Shield Gateway / Engine** | Node.js $\ge 20.10.0$ LTS, TypeScript $\ge 5.3$ | 1 vCPU, 512 MB RAM | Docker Container (distroless / Alpine Linux), Kubernetes Sidecar |
| **Enterprise Intelligence Service** | Node.js $\ge 20.10.0$ LTS | 1 vCPU, 512 MB RAM | Render Web Service / Private Isolated Network VPC |
| **Licensing & Control Plane** | Next.js 16.3.4+, React 19, Supabase SSR | Serverless Node.js 20 runtime | Vercel Edge/Serverless + Supabase Enterprise Postgres |
| **MCP Protocol Specification** | Model Context Protocol Specification `2024-11-05` and subsequent stable revisions | stdio, SSE (Server-Sent Events), WebSocket transports | Subprocess stdio or authenticated TLS reverse-proxy SSE |

---

## 3. Service Level Objectives (SLOs) & Deployment Modes

### Deployment Modes
1. **Embedded Library Mode**: In-process Node.js library imported via `import { wrapToolServer } from 'mcpshld'`. Operates with sub-millisecond local evaluation and zero network hops.
2. **Reverse Proxy / Sidecar Mode**: Local stdio or HTTP/SSE sidecar container running adjacent to the MCP tool host.
3. **Enterprise Cloud Gateway Mode**: Authenticated multi-tenant proxy terminating TLS, querying the private Enterprise Intel service, and enforcing cryptographic policy bundles.

### Latency & Availability SLOs
- **Decision Latency P50**: $\le 250\ \mu\text{s}$ (local pipeline deterministic analysis).
- **Decision Latency P95**: $\le 500\ \mu\text{s}$ (full composite pipeline evaluation).
- **Decision Latency P99**: $\le 15{,}000\ \mu\text{s}$ (hard ceiling under heavy load).
- **Throughput Capacity**: $\ge 10{,}000$ tool calls/sec on single commodity vCPU.
- **Availability Target**: 99.95% uptime for Enterprise Intel and Licensing Control Plane.
- **Circuit Breaker Fail-Closed Threshold**: 3 consecutive remote timeouts ($\ge 200\text{ ms}$) triggers local fail-closed containment mode.

---

## 4. Trust Boundaries & Architecture Topology

```
+-----------------------------------------------------------------------------------+
| Host AI Application / LLM Client (Claude Desktop, Cursor, IDE, LangChain)       |
+-----------------------------------------------------------------------------------+
                                         │ JSON-RPC 2.0 (stdio / SSE)
                                         ▼
=====================================================================================
TRUST ZONE 1: MCP Shield Gateway & Execution Broker (Local / Sidecar)
  - IngressGuard (Protocol, Schema, Depth, Recursion, Key limits)
  - ToolGuard (Capability derivation, AST Firewall, Deobfuscation)
  - OutputGuard (Bijective DLP Sanitizer, Canary Probe Detection)
  - ExecutionBroker (OS Subprocess Sandbox, Egress Socket Pinning)
=====================================================================================
           │                                                  │
           │ HTTPS + Ed25519 / HMAC                           │ HTTPS + Scoped API Key
           ▼                                                  ▼
+───────────────────────────────+                 +───────────────────────────────+
| TRUST ZONE 2: Licensing Plane |                 | TRUST ZONE 3: Enterprise Intel|
| (mcp-shield-licensing)        |                 | (mcp-shield-enterprise-intel) |
| - Ed25519 License Verification|                 | - Opaque Risk Decision API    |
| - Signed Policy Manifests     |                 | - Non-linear Risk Scoring     |
| - Server-Side Stripe Billing  |                 | - Behavioral Kill-Chains      |
| - Privacy-Redacted Telemetry  |                 | - Hardened Crown-Jewel Vault  |
+───────────────────────────────+                 +───────────────────────────────+
           │                                                  │
           ▼                                                  ▼
+───────────────────────────────+                 +───────────────────────────────+
| TRUST ZONE 4: Persistence     |                 | Downstream Target MCP Servers |
| Supabase RLS / Postgres       |                 | (Filesystem, Postgres, Git)   |
+───────────────────────────────+                 +───────────────────────────────+
```

### Trust Boundary Rules
1. **Engine to Host**: Never forward unvalidated error structures, unredacted tokens, or downstream raw exceptions to the host LLM.
2. **Engine to Target Tools**: Downstream tools are untrusted. Self-declared capability claims (`_shieldCapabilities`) are strictly downgraded to untrusted unless cryptographically signed.
3. **Engine to Enterprise Intel**: Engine sends bounded feature vectors (max 64KB). Intel service returns opaque verdicts, risk bands, and safe reason codes; never leaks proprietary corpus signatures or raw internal heuristic constants to client bundles.
4. **Engine to Licensing Plane**: Telemetry events must be authenticated via per-project keys, validated against strict schemas, bounded in size, and stripped of raw sensitive tool arguments or credentials.

---

## 4. Threat Model & Security Invariants

### 18-Vector Formal Threat Model
1. **Prompt Injection & Parameter Escaping**: Injection of metacharacters, prompt overrides, or system prompts inside tool parameters.
2. **AST Parser Differential Evasion**: Discrepancies between security parser interpretation and target interpreter execution.
3. **Subprocess Escape & Command Injection**: Execution of unauthorized binaries, shell chaining (`&&`, `|`, `;`), or command substitution.
4. **Symlink / Path Traversal**: Directory escapes (`../../etc/passwd`), UNC paths (`\\server\share`), and alternate data streams (`::$DATA`).
5. **Egress TOCTOU & DNS Rebinding**: Resolving an allowed public host, followed by rapid DNS shift to private IPs (`127.0.0.1`, `169.254.169.254`).
6. **Tool Poisoning & Dynamic Mutation**: Malicious runtime changes to tool signatures or parameter schemas designed to mislead models.
7. **Downstream Capability Attestation Spoofing**: Tools claiming vaulted secret scopes or elevated network privileges via unchecked schema fields.
8. **Credential & Secret Exfiltration (DLP)**: Outbound transmission of API keys, RSA keys, AWS secrets, or JWT tokens.
9. **Multi-Turn Behavioral Kill-Chains**: Staged attacks where reconnaissance in Turn 1 leads to staging in Turn 2 and detonation in Turn 3.
10. **State Poisoning via Tool Outputs**: Tool outputs containing poisoned instructions intended to hijack LLM conversation state.
11. **Cyclic Reflection Exploits**: Self-referential loop generation consuming context limits or inducing infinite execution trees.
12. **Protocol Resource Exhaustion (DoS)**: JSON-RPC recursion bombs, oversized batches, or Slowloris connections.
13. **Tenant IDOR & Cross-Org Access**: Unauthorized read/write of projects, API keys, or policies across organizational boundaries.
14. **API Key Verifier Exposure**: Storage or retrieval of raw API secrets instead of irreversible cryptographic verifiers.
15. **Billing Entitlement Spoofing**: Client-side tampering with subscription status or organization tiering.
16. **Telemetry Replay & Tampering**: Modification or replay of telemetry batches to mask security incidents.
17. **Model Poisoning & Adversarial Inputs**: Sending NaN, Infinity, negative values, or crafted features to skew risk algorithms.
18. **Dependency & Supply Chain Compromise**: Malicious dependencies, unverified transitive packages, or modified lockfiles.

### Core Security Invariants
- **Fail-Closed by Default**: Any internal failure, syntax ambiguity, unknown tool, expired signature, or missing credential halts execution with an explicit block.
- **Zero Raw Secrets**: API keys, signing secrets, and webhook tokens are never stored in plaintext, never logged, and never included in telemetry.
- **Constant-Time Verification**: All token, HMAC, signature, and password verifications use constant-time comparisons (`crypto.timingSafeEqual`).
- **Idempotent Operations**: All state-changing billing webhooks, key rotations, and policy updates support deduplicated replay safety.
- **Strict Server Authoritativeness**: Client-supplied claims regarding roles, entitlements, pricing, or risk scores are discarded.

---

## 5. Service Level Objectives (SLOs) & Performance Budgets

| Metric | Target | Measurement Method | Failure Action |
| :--- | :--- | :--- | :--- |
| **Gateway Decision Latency (P50)** | $< 250\,\mu\text{s}$ | In-process stage benchmark (`bench:stages`) | Fail perf gate CI |
| **Gateway Decision Latency (P95)** | $< 500\,\mu\text{s}$ | In-process stage benchmark | Fail perf gate CI |
| **Gateway Decision Latency (P99)** | $< 1.0\,\text{ms}$ | Full proxy latency benchmark | Fail perf gate CI |
| **DLP Streaming Throughput** | $> 50\,\text{MB/s}$ | Memory-bounded sliding window benchmark | Optimize regex |
| **Intel Remote Decision Latency** | $< 25\,\text{ms}$ | Remote HTTP endpoint benchmark | Circuit breaker trigger |
| **Gateway Availability** | $99.95\%$ | Process health / liveness check | Container restart |
| **Licensing API Availability** | $99.90\%$ | Vercel Edge runtime monitoring | Edge failover |
| **Enterprise Intel Availability** | $99.90\%$ | Render Health check `/health` | Fail-closed / fallback |

---

## 6. Payload Limits, Bounds & Resource Constraints

- **Maximum JSON-RPC Message Size**: 1 MB (`1,048,576` bytes). Messages exceeding this are immediately dropped with HTTP 413 / JSON-RPC `-32600`.
- **Maximum AST Recursion Depth**: 32 nested levels.
- **Maximum Object Key Count**: 5,000 keys per JSON payload.
- **Maximum Batch Request Size**: 50 calls per JSON-RPC batch.
- **Enterprise Intel Max Payload**: 64 KB (`65,536` bytes).
- **Telemetry Ingestion Max Payload**: 100 events / 256 KB per batch.
- **Policy Bundle Max Size**: 512 KB.
- **Subprocess Execution Limits**:
  - Wall-clock timeout: 10,000 ms (configurable per policy).
  - Maximum stdout/stderr buffer: 2 MB.
  - Process memory limit: 512 MB.

---

## 7. Data Classification, Privacy & Retention Policies

| Data Class | Examples | Encryption at Rest | Encryption in Transit | Retention Period | Deletion Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Class 1: Public** | Documentation, open schemas, public signatures | N/A | TLS 1.3 | Indefinite | Git commit history |
| **Class 2: Operational** | Health metrics, request IDs, aggregated counts | AES-256 (GCM) | TLS 1.3 | 90 days | Automatic TTL purge |
| **Class 3: Customer Metadata** | Org names, user emails, project slugs | AES-256 (GCM) | TLS 1.3 | Active account + 30 days | Self-serve GDPR delete API |
| **Class 4: Confidential Telemetry** | Security event types, detector IDs, tool names | AES-256 (GCM) | TLS 1.3 (HMAC-SHA256) | 30 days | Rolling partition deletion |
| **Class 5: Restricted / Trade Secret** | Intel attack corpus, scoring weights, private keys | AES-256-GCM / KMS | TLS 1.3 + Mutual Auth | Permanent internal | Strict access revoke |

*Strict Invariant*: Raw tool arguments, raw secrets intercepted by DLP, full database query contents, and full prompts are NEVER written to persistent database storage or application logs.

---

## 8. Backup, Disaster Recovery & Business Continuity

- **Recovery Point Objective (RPO)**: $< 1$ hour.
- **Recovery Time Objective (RTO)**: $< 4$ hours.
- **Database Backup Frequency**: Continuous WAL archiving + daily automated snapshots via Supabase Enterprise.
- **Backup Encryption**: AES-256 with KMS managed keys isolated from application runtime.
- **Stripe Reconciliation**: Daily automated reconciliation job (`mcp-shield-licensing/scripts/reconcile-stripe-subscriptions.ts`) compares local subscription state against Stripe Subscription API to detect and correct out-of-band drifts.
- **Disaster Recovery Drill**: Automated drill script (`scripts/disaster-recovery-drill.ts`) simulates snapshot checksum validation, KMS asymmetric key recovery, and telemetry backlog replay within RPO/RTO bounds.

---

## 9. Dependency, Vulnerability & Release Policies

- **Lockfile Integrity**: All dependencies must be strictly locked via `package-lock.json` with SHA-512 integrity hashes.
- **Automated Scanning**:
  - `npm audit`: Zero `HIGH` or `CRITICAL` vulnerabilities permitted in production builds.
  - SAST / Secret Scanning: CI blocks merge if any high-entropy token or private key is detected.
- **Release Manifest**: Every production release requires an immutable manifest containing:
  - Git commit SHA
  - Semantic Version
  - Lockfile SHA-256
  - Policy engine version
  - Build timestamp and signatures

---

## 10. Explicit Non-Goals & Boundaries

1. **Not a General-Purpose WAF**: MCP Shield is specifically designed for agent-to-tool and model-context boundaries; it does not replace network perimeter firewalls.
2. **Not a Code Interpreter Sandbox**: MCP Shield mediates capability requests; where subprocesses run, platform OS isolation (Docker/gVisor/seccomp) must be provided by the host environment.
3. **No 100% Detection Guarantees**: Detection is probabilistic and defense-in-depth. We state verifiable empirical metrics (Precision, Recall, F1) on documented benchmark sets, never unqualified "100% security" claims.
