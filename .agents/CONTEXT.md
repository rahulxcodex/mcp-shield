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
  - Endpoint: `https://mcp-shield-enterprise-intel.onrender.com/api/v1/intel/scoring` (Status: LIVE).
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
- **GitHub**: All 3 repositories synced and audited; 55 suites / 780 tests passing cleanly.
- **Vercel**: `mcp-shield-dashboard` deployed in READY state, `mcp-shield-licensing` verified and building cleanly with Turbopack.
- **Render**: `mcp-shield-enterprise-intel` hardened with fail-closed authentication and connection timeouts.
