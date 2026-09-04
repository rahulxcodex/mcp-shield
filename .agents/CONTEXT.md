# MCP Shield - Multi-Repo System Context

## 1. System Topology & 3-Repository Ecosystem
- **`mcp-shield`** (Public GitHub `rahulxcodex/mcp-shield`, npm package `mcpshld` v1.0.23):
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
- **npm**: `mcpshld` v1.0.23 published with public access (circular dependency removed, exports map configured).
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

## 6. Testing, Performance & Maintainability (Step 2 Roadmap Complete)
- **Security-Weighted Coverage & Mutation Resistance**: `jest.config.js` and `scripts/security-coverage-gate.ts` enforce module gates (Path Resolver $\ge 98\%$, Egress $\ge 98\%$, Policy $\ge 95\%$, Protocol $\ge 95\%$). `src/security/mutation/mutation-engine.ts` achieves $100\%$ mutation score across 9 critical mutation operators (`npm run test:mutations`).
- **Adversarial Generator & Attack Paths**: `src/security/adversarial/adversarial-generator.ts` generates 17-family mutation variants. `src/security/attack-path/attack-path-engine.ts` blocks multi-tool exfiltration kill-chains. `src/security/attack-path/customer-fuzzer.ts` provides automated path discovery.
- **Protocol Property Testing & Differential Regressions**: `tests/security-corpus/protocol-property-based.test.ts` (fast-check) verifies 4 protocol invariants. `src/security/differential/differential-runner.ts` tests conformance. `tests/security/cross-platform-matrix.test.ts` covers Linux, Windows, macOS.
- **Single Security Envelope & Streaming DLP**: `src/core/security-envelope.ts` eliminates repeated parse cycles; `OutputGuard` performs in-place sanitization. `src/security/dlp/incremental-secret-scanner.ts` provides $O(1)$ memory streaming secret detection with 128-byte sliding overlap.
- **Normalized IR & Resource Budgets**: `src/security/ir/` translates shell/powershell/cmd to `SecurityCommandIR`. `src/security/budget/security-budget.ts` bounds execution limits.
- **Master Regression Gate & Benchmarks**: `npm run bench:stages` breaks down 9 pipeline stages ($P50=194\,\mu\text{s}$, $P95=389\,\mu\text{s}$, $P99=473\,\mu\text{s}$). `npm run test:security-gate` orchestrates full verification and generates `security-report.json`.
- **Test Suite Status**: 85 suites / 898 tests passing cleanly ($100\%$).

## 7. ML Security Intelligence & Sustainable Competitive Moat (Step 3 Roadmap Complete)
- **Hybrid Security Architecture**: Deterministic hard blocks (Protocol, Policy, DLP/AST) remain strictly authoritative. ML models boost suspicion, provide explainable evidence, and recommend stronger controls (`MONITOR`, `PROMPT`, `SANDBOX`, `QUARANTINE`, `BLOCK`).
- **Model A — Tabular Tool/Action Risk Model**: `src/security/ml/models/tabular-risk-model.ts` evaluates 42 versioned features across tool complexity, request entropy/encodings, behavioral transitions, and provenance; outputs calibrated attack probability, novelty score, and SHAP-style primary signals in $< 200\,\mu\text{s}$.
- **Model B — Text Security Classifier**: `src/security/ml/models/text-security-classifier.ts` classifies tool descriptions, schemas, outputs, and documentation into `BENIGN`, `SUSPICIOUS`, `PROMPT_INJECTION`, `TOOL_POISONING`, and `DATA_EXFILTRATION`.
- **Model C — Behavioral Anomaly Detection**: `src/security/ml/models/behavior-anomaly-detector.ts` tracks Markov tool and capability transitions, flagging new capabilities, privilege escalation leaps, and novel destinations.
- **Online Novelty & Schema Drift Intelligence**: `src/security/ml/novelty-scorer.ts` and `src/security/ml/schema-drift-detector.ts` fingerprint schema changes with RFC 8785 hashes and detect capability expansion events (e.g. read -> read + network egress) before execution.
- **Unified Security Graph & Attack Path Engine**: `src/security/graph/security-graph.ts` models tools, identities, capabilities, data assets, and sinks, calculating BFS/Dijkstra minimum attack paths and blast radius.
- **Environment-Specific Attack Discovery**: `src/security/graph/environment-scanner.ts` scans customer MCP tool manifests, enumerates dangerous multi-tool compositions, and generates synthetic attack payloads and remediation instructions.
- **Proprietary Attack Corpus & Adversarial Learning Loop**: `src/security/ml/proprietary-attack-corpus.ts` and `src/security/ml/adversarial-learning-loop.ts` store confirmed security incidents, mine hard negatives from reviewed decisions, synthesize adversarial attack variants, and prevent unreviewed model poisoning.
- **Privacy-Preserving Telemetry**: `src/security/ml/privacy-telemetry.ts` transmits capability vectors and feature digests instead of raw payload bodies across 4 enterprise modes (`cloud-intel`, `private-telemetry`, `self-hosted`, `air-gapped`).
- **Rigorous Evaluation & Version Identity**: `src/security/ml/evaluation/model-evaluator.ts` implements temporal, server, and attack-family holdout splits, ROC-AUC/PR-AUC, and Brier calibration scores.
- **Colab & Production ML Pipeline**: `notebooks/mcp_shield_ml_training.ipynb` (Colab), `scripts/ml/` (VIF < 2.3, Breusch-Pagan heteroscedasticity p < 1e-300, 5-fold isotonic calibration), `deployment/` (FastAPI / Hugging Face Spaces / Render free tier).
- **Protocol-Neutral Agent Security Kernel**: `src/security/kernel/agent-security-kernel.ts` with pluggable adapters (`McpProtocolAdapter`, `BrowserProtocolAdapter`, `CodingProtocolAdapter`), executing unified security controls across AI agent ecosystems.
- **Verification Gate**: 85 suites / 898 tests passing cleanly with zero regressions.

## 8. v2.0.0 Production Hardening, Intelligence Bus & Attack Coverage (Complete)
- **Fail-Closed Auth & Zero Fallbacks**: `cloud-dashboard/src/middleware.ts` fails closed on auth backend errors in production (503/401); all hardcoded credential strings purged; `src/security/authz/authorization-service.ts` and `cloud-dashboard/src/lib/authz.ts` enforce 14 standard actions and multi-tenant isolation across all dashboard routes.
- **Canonical Security Decision**: `src/security/decision.ts` provides immutable internal contract (`requestId`, `action`, `riskScore`, `detectorIds`, `attackPathIds`, `capabilities`, `provenance`, `redactions`, `modelSignals`, `enforcementSource`).
- **Production Merkle Audit Ledger**: `src/security/audit-ledger.ts` implements monotonic sequence numbers, chained HMAC digests ($H_n = \text{HMAC}(H_{n-1} \parallel \dots)$), periodic rolling Merkle tree roots, durable sink interfaces, and mathematical integrity verification utility.
- **Cryptographic JIT Quorum**: `src/security/authorization.ts` implements real asymmetric/HMAC signature verification, nonce replay prevention, action/org binding, and four-eyes quorum enforcement.
- **Authoritative Egress Engine**: `src/security/egress/egress-engine.ts` provides pre-flight DNS resolution, DNS rebinding attack defense, socket IP pinning, and redirect chain inspection.
- **Blast-Radius & Provenance Engine**: `src/security/blast-radius/blast-radius-engine.ts` computes 7-vector blast radius; `src/security/provenance/provenance-manager.ts` tracks package identity, binary digest, and incident history.
- **Policy-Aware Schema Drift**: `src/security/ml/schema-drift-detector.ts` classifies drift into 8 categories (`CREDENTIAL_EXPANSION`, `NETWORK_EXPANSION`, `EXECUTION_EXPANSION`, etc.) mapped to policy actions.
- **Security Intelligence Bus & Signal Fusion**: `src/security/intelligence/intelligence-bus.ts` defines typed `SecuritySignal` and deterministic fusion with hard-block precedence.
- **Model Governance Registry**: `src/security/ml/governance/model-registry.ts` manages model promotion lifecycle (`SHADOW` -> `CANARY` -> `PRODUCTION`), cryptographic digests, performance gates, and zero-downtime rollback.
- **Security Replay Engine**: `src/security/replay/security-replay-engine.ts` evaluates historical `.jsonl` traffic; exposed via CLI command `mcp-shield replay-eval <log>`.
- **Distributed State & Tenant Isolation Tests**: `src/cloud/state/distributed-state-adapter.ts`, `cloud-dashboard/tests/auth/route-auth-matrix.test.ts`, and `cloud-dashboard/tests/tenancy/tenant-isolation.test.ts`.
- **Release Verification**: 97 suites / 941 tests passing ($100\%$), 46/46 attack-family matrix checks passing ($100\%$), and 9/9 mutation operators killed ($100\%$).

## 9. Multi-Model ML Suite, Deployment Keep-Alive & Direct Mail API (v1.0.24)
- **4-Model ML Intelligence Suite**: Aligned with `ML_ROADMAP_GOOGLE_COLAB.md`. Model A (Calibrated Tabular Risk, Brier=0.0003), Model B (Attack Family Classifier across 10 families, 100% accuracy), Model C (Behavioral Sequence Trajectory Risk, ROC-AUC=0.8125), and Model D (Novelty & Outlier Anomaly Isolation Forest).
- **Hugging Face Spaces & Gradio 6.0**: Multi-model visualization tabs and programmatic `/api/predict` endpoint in `deployment/app.py` with zero deprecated parameter warnings.
- **Deployment Keep-Alive Automation**: `.github/workflows/render-keepalive.yml` runs every 10 minutes (`*/10 * * * *`) pinging Render Enterprise Intel and Hugging Face Spaces with cold-start retry tolerances.
- **Direct Mail API Transition**: `cloud-dashboard/src/lib/email-service.ts` dispatches support inquiries directly via Resend REST API (`RESEND_API_KEY`) and SendGrid API with Apps Script fallback.
- **Trade Secret Boundaries**: Delineated and strictly isolated across the 3 repositories (`mcp-shield` public, `mcp-shield-enterprise-intel` private on Render, `mcp-shield-licensing` private on Vercel).
