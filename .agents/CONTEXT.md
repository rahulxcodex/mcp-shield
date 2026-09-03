# MCP Shield - Multi-Repo System Context

## 1. System Topology & 3-Repository Ecosystem
- **`mcp-shield`** (Public GitHub `rahulxcodex/mcp-shield`, npm package `mcpshld` v1.0.20):
  - Zero-Trust Security Gateway, AST Firewall & Bijective DLP Sanitizer for Model Context Protocol (MCP).
  - Web Platform & Console: Next.js 16 App Router on Vercel (`mcp-shield-dashboard.vercel.app`).
  - Open Security Benchmark Suite: 50 suites / 717 tests covering AST evasion, DLP, memory bounds, COW race locks, and security invariants.
  - License Verification: Client-side cryptographic Ed25519 signature verification using public key.
- **`mcp-shield-enterprise-intel`** (Private GitHub `rahulxcodex/mcp-shield-enterprise-intel`, Render Web Service):
  - Proprietary non-linear risk scoring algorithm (`AST_COMPLEXITY_EXPONENT`, `EGRESS_SEVERITY_MULTIPLIER`, `DRIFT_BASE_PENALTY`).
  - Endpoint: `https://mcp-shield-enterprise-intel.onrender.com/api/v1/intel/scoring` (Status: LIVE).
  - Trade Secret Boundary: Excluded from public binaries and repositories.
- **`mcp-shield-licensing`** (Private GitHub `rahulxcodex/mcp-shield-licensing`, Vercel App):
  - Asymmetric cryptographic license generation (`/api/license`) using Ed25519 private key.
  - Anti-sybil GitHub account age validation (>1 year account required).
  - Stripe billing, subscription webhooks, and Supabase multi-tenant organization state.
  - Endpoint: `https://mcp-shield-licensing.vercel.app` (Status: READY).

## 2. Security Hardening & Trade Secret Invariants
- **Atomic Rate Limiting**: Check-and-reserve model prevents quota exhaustion by blocked attacks.
- **COW Race Defense**: Canonical path mutex + randomized staging suffixes eliminate TOCTOU overwrite races.
- **Secret Vault Scoping**: 10MB memory bound with LRU eviction; scoped HMAC deduplication; context-bound restoration.
- **Whole-Envelope DLP**: Outbound sanitization covers all `params`, `error`, and `result` envelopes.
- **Dashboard URL & XSS Protection**: HttpOnly SameSite=Strict session cookie + 302 redirect + HTML entity escaping on WebSocket events.
- **No Private Keys in Open Source**: Ed25519 signing private keys only exist in Vercel KMS/env (`LICENSE_PRIVATE_KEY`). Fail-closed enforcement.
- **No Backdoors in Code**: Master license keys verified strictly via explicit server environment variables; backdoor paths purged.
- **Authoritative Payment Validation**: Razorpay verification enforces server-side plan and seat consistency.
- **Strict Separation of Scoring Weights**: Proprietary non-linear scoring stays isolated in `mcp-shield-enterprise-intel`.

## 3. Deployment & Release Matrix
- **npm**: `mcpshld` v1.0.20 published with public access.
- **GitHub**: All repositories synced with passing CI checks and PR #23 merged.
- **Vercel**: `mcp-shield-dashboard` deployed in READY state (`4e97fe5e`).
- **Render**: `mcp-shield-enterprise-intel` deployed in LIVE state (verified `/health`).
