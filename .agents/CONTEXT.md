# MCP Shield - Multi-Repo System Context

## 1. System Topology & 3-Repository Ecosystem
- **`mcp-shield`** (Public GitHub `rahulxcodex/mcp-shield`, npm package `mcpshld` v1.0.21):
  - Zero-Trust Security Gateway, AST Firewall & Bijective DLP Sanitizer for Model Context Protocol (MCP).
  - Web Platform & Console: Next.js 16 App Router on Vercel (`mcp-shield-dashboard.vercel.app`).
  - Open Security Benchmark Suite: 50 suites / 719 tests covering AST evasion, DLP, memory bounds, COW race locks, and security invariants.
  - License Verification: Constant-time master key verification (`crypto.timingSafeEqual`) and Ed25519 signature checks.
- **`mcp-shield-enterprise-intel`** (Private GitHub `rahulxcodex/mcp-shield-enterprise-intel`, Render Web Service):
  - Proprietary non-linear risk scoring algorithm (`AST_COMPLEXITY_EXPONENT`, `EGRESS_SEVERITY_MULTIPLIER`, `DRIFT_BASE_PENALTY`).
  - Endpoint: `https://mcp-shield-enterprise-intel.onrender.com/api/v1/intel/scoring` (Status: LIVE).
  - Trade Secret Boundary: Hardened with 64KB max body limit, constant-time API key auth, and numeric input sanitization.
- **`mcp-shield-licensing`** (Private GitHub `rahulxcodex/mcp-shield-licensing`, Vercel App):
  - Asymmetric cryptographic license generation (`/api/license`) using Ed25519 private key.
  - Hardened with organization membership checks (IDOR fix), role escalation protection, and timing-safe telemetry HMAC verification.
  - Endpoint: `https://mcp-shield-licensing.vercel.app` (Status: READY).

## 2. Security Hardening & Trade Secret Invariants
- **Atomic Rate Limiting**: Check-and-reserve model prevents quota exhaustion by blocked attacks.
- **COW Race Defense**: Canonical path mutex + randomized staging suffixes eliminate TOCTOU overwrite races.
- **Secret Vault Scoping**: 10MB memory bound with LRU eviction; scoped HMAC deduplication; context-bound restoration.
- **Whole-Envelope DLP**: Outbound sanitization covers all `params`, `error`, and `result` envelopes + modern GitHub token prefixes (`ghu_`, `ghs_`, `ghr_`).
- **Dashboard URL & XSS Protection**: HttpOnly SameSite=Strict session cookie + 302 redirect + HTML entity escaping on WebSocket events.
- **No Private Keys in Open Source**: Ed25519 signing private keys only exist in Vercel KMS/env (`LICENSE_PRIVATE_KEY`). Fail-closed enforcement.
- **Zero Backdoors**: All test keys and plaintext secret fallbacks purged; constant-time comparison enforced across all auth boundaries.
- **Authoritative Payment Validation**: Whitelisted Stripe price IDs and server-side membership verification.
- **Strict Separation of Scoring Weights**: Proprietary non-linear scoring stays isolated in `mcp-shield-enterprise-intel`.

## 3. Deployment & Release Matrix
- **npm**: `mcpshld` v1.0.21 published with public access.
- **GitHub**: All 3 repositories synced (`rahulxcodex/mcp-shield` PR #25 merged, `rahulxcodex/mcp-shield-enterprise-intel` commit `dc072ed`, `rahulxcodex/mcp-shield-licensing` commit `ea1fcd6`).
- **Vercel**: `mcp-shield-dashboard` deployed in READY state (`18d5c63e`), `mcp-shield-licensing` deployed in READY state (`ea1fcd6d`).
- **Render**: `mcp-shield-enterprise-intel` deployed in LIVE state (`dc072edc`).
