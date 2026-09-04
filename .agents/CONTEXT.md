# MCP Shield - Multi-Repo System Context

## 1. System Topology & 3-Repository Ecosystem
- **`mcp-shield`** (Public GitHub `rahulxcodex/mcp-shield`, npm package `mcpshld` v1.0.22):
  - Zero-Trust Capability Execution Broker, AST Firewall & Bijective DLP Sanitizer for Model Context Protocol (MCP).
  - Decomposed Modular Pipeline: IngressGuard, ToolGuard, ExecutionBroker, OutputGuard, and LifecycleManager.
  - Web Platform & Console: Next.js 16 App Router on Vercel (`mcp-shield-dashboard.vercel.app`).
  - Open Security Benchmark Suite: 55 suites / 780 tests covering AST evasion, differential parsing, mutation sensitivity, DLP held-out benchmarks, COW race locks, and protocol validation bounds.
  - Advanced Detection: Unicode homoglyph/zero-width normalizer, multi-interpreter execution & chaining analyzer, and 18-vector formal threat model matrix.
  - License Verification: Constant-time master key verification (`crypto.timingSafeEqual`), finite positive expiry timestamp checks, and Ed25519 signature checks.
- **`mcp-shield-enterprise-intel`** (Private GitHub `rahulxcodex/mcp-shield-enterprise-intel`, Render Web Service):
  - Proprietary non-linear risk scoring algorithm (`AST_COMPLEXITY_EXPONENT`, `EGRESS_SEVERITY_MULTIPLIER`, `DRIFT_BASE_PENALTY`).
  - Proprietary weaponized attack corpus & multi-turn behavioral kill chains (`CHAIN-EXFIL-001`, `CHAIN-STAGE-DETONATE-001`).
  - Endpoints: `/api/v1/intel/scoring`, `/api/v1/intel/threat-corpus`, `/api/v1/intel/behavioral-rules` (Status: LIVE on Render).
  - Trade Secret Boundary: Hardened with 64KB max body limit, fail-closed constant-time API key auth, Slowloris timeouts, and numeric input sanitization.
- **`mcp-shield-licensing`** (Private GitHub `rahulxcodex/mcp-shield-licensing`, Vercel App):
  - Asymmetric cryptographic license generation (`/api/license`) using Ed25519 private key.
  - Hardened with organization membership checks (IDOR fix), role escalation protection, robust account creation date parsing, and timing-safe telemetry HMAC verification.
  - Endpoint: `https://mcp-shield-licensing.vercel.app` (Status: READY).

## 2. Security Hardening & Trade Secret Invariants
- **Capability-Enforced Execution Broker**: Enforces cryptographic capability manifests (`tool identity -> allowed capabilities -> allowed resources -> egress domains -> secret scopes`); blocks unknown tools by default (`UNKNOWN_TOOL_BLOCKED`).
- **Egress TOCTOU & Socket-Layer Pinning**: Pins DNS lookups at `http.Agent.lookup` to prevent rebinding races; intercepts 3xx redirects to block redirection to internal IPs or AWS metadata (`169.254.169.254`). Default-deny for production profiles (`allowMode: 'deny'`).
- **Strict JSON-RPC Protocol Validation**: Bounds recursion depth (max 32), key count limits (max 5000), duplicate in-flight request IDs, and output amplification ceiling (max 1 MB).
- **Tool Poisoning & Schema Pinning Defense**: Fail-closed abort on dynamic tool mutation or schema violation; drops malicious tools/list payloads immediately before delivery to host LLM.
- **Untrusted Schema Attestation Trap**: Downstream untrusted tools cannot self-attest `secretAccess` via schema properties; prevents automated exfiltration of vaulted credentials.
- **PowerShell & cmd.exe AST Evasion Immunity**: Normalizes colon argument syntax (`-enc:BASE64`, `-e:BASE64`) and deobfuscates carets (`%A^WS%`) before environment variable scanning.
- **Fail-Closed Intel Authentication**: Eliminated fallback regex in Render service; strictly requires server-side secret keys.
- **Atomic Rate Limiting**: Check-and-reserve model prevents quota exhaustion by blocked attacks.
- **COW Race Defense**: Canonical path mutex + randomized staging suffixes eliminate TOCTOU overwrite races.
- **Secret Vault Scoping**: 10MB memory bound with LRU eviction; scoped HMAC deduplication; fail-closed context binding.
- **Whole-Envelope DLP**: Outbound sanitization covers all `params`, `error`, and `result` envelopes + modern GitHub token prefixes (`ghu_`, `ghs_`, `ghr_`).
- **Dashboard URL & XSS Protection**: Constant-time token verification + HttpOnly SameSite=Strict session cookie + 302 redirect + HTML entity escaping on WebSocket events.
- **No Private Keys in Open Source**: Ed25519 signing private keys only exist in Vercel KMS/env (`LICENSE_PRIVATE_KEY`). Fail-closed enforcement.
- **Zero Backdoors**: All test keys and plaintext secret fallbacks purged; constant-time comparison enforced across all auth boundaries.

## 3. Deployment & Release Matrix
- **npm**: `mcpshld` v1.0.22 published with public access (circular dependency removed, exports map configured).
- **GitHub**: All 3 repositories synced and audited; PR #31 merged to `main` (`cf45a47`); 55 suites / 780 tests passing cleanly.
- **Vercel**: `mcp-shield-dashboard` deployed in READY state (`dpl_44ReRsnLP23n8LEYjJ4BKFkMNTZE`), `mcp-shield-licensing` verified and building cleanly with Turbopack.
- **Render**: `mcp-shield-enterprise-intel` live with commit `43cc006`, exposing authenticated threat corpus, behavioral kill-chain, and risk scoring APIs.

## 4. Commercial Architecture, Referral Engine & Customer Verification
- **Pricing & Tiering Logic**: Defined in `src/config/plans.ts`. Starter plan configured at 10 USD/year (or 1 USD/month). Active payment gateways kept dormant in code (`SHOW_PAYMENT_GATEWAYS: false`) during the introductory free access rollout (`FREE_ACCESS_LIMITED_PERIOD: true`).
- **Single Active Key Policy**: Strictly enforces `maxActiveKeys: 1` per account on key generation and key import. Automatically rotates prior active keys to epoch timestamp (`expires_at = 1970-01-01`).
- **Key Non-Reusability**: Historical SHA-256 hash lookup rejects any previously revoked or used keys with 400 Bad Request, guaranteeing one-time issuance semantics.
- **Referral Engine**: Deterministic `SHIELD-<id>` codes granting 30 days (1 month) of free access to referees upon redemption; blocks self-referral attempts.
- **UI & Metrics Authenticity**: Removed all mock/random numbers from `/console` and settings pages. Baseline metrics default cleanly to 0. Master key import (`MASTER_*` / `MCP_SHIELD_MASTER_KEY`) elevates user with master admin badges.
- **Playwright Customer Testing**: Automated suite in `scripts/test-customer-agents.js` executing 5 customer subagents covering metrics integrity, single-key limit, master import, referral redemption, and non-reusability (5/5 passing).

## 5. Security Kernel & Architecture Hardening (Step 1 Roadmap Complete)
- **Canonical Security Pipeline**: `src/core/pipeline/security-pipeline.ts` provides a 7-stage pipeline (`Normalize` -> `Parse/Classify` -> `Capability Extraction` -> `Deterministic Detectors` -> `Attack-Path Analysis` -> `Risk Scoring` -> `Policy Decision`) with shared `SecurityContext`.
- **Deduplicated Interpreter Analysis**: `src/security/interpreter-analyzer.ts` with `UnifiedInterpreterClassifier` and pluggable `InterpreterAnalyzer` eliminating redundant multi-pass AST execution.
- **Capability Trust Hierarchy**: 5-tier resolution (Admin Policy > Signed Manifest > Verified Publisher > Local Inference > Untrusted Self-Declaration) downgrading downstream `_shieldCapabilities` strictly to `untrusted`.
- **Canonical Path Resolver**: `src/security/path-resolver.ts` (`PathSecurityResolver`) enforcing Unicode NFKC, recursive URL decoding, UNC, Windows drive, dot-segments, and `isWithin` containment.
- **Canonical JSON**: `src/security/canonical-json.ts` (RFC 8785 deterministic key sorting & stable `hashCanonicalJson` digests).
- **Real Cancellation Propagation**: `src/core/dispatcher.ts` with `ExecutionContext` and `AbortController` propagation across dispatcher, execution broker, and subprocesses.
- **Removed Placeholders**: `src/security/feature-flags.ts` with explicit `FeatureStatus: 'UNSUPPORTED'` and fail-closed handling for CAC/PIV, SLSA L4, CRDT HA, NVMe WAL.
- **Hardened WASM Plugins**: `src/microkernel/wasm-loader.ts` with publisher allowlists, constant-time SHA-256 digests, cryptographic signatures, memory limits, and fail-closed execution.
- **Library / CLI Split**: `src/index.ts` is pure library exports with zero side effects; `src/cli.ts` handles command routing; `bin/mcp-shield.js` invokes CLI.
- **Dependency Injection**: `src/core/runtime/security-runtime.ts` (`SecurityRuntime`) managing SessionStore, BehaviorStore, ReputationStore, ThreatCorpusStore, FeatureStore.
- **Universal Evidence Contract**: `src/security/evidence.ts` (`SecurityEvidence` and `ThreatCategory`).
