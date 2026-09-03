# MCP Shield - Project Context

## Project Architecture
- Core: Zero-Trust Security Gateway, AST Firewall & Bijective DLP Sanitizer for Model Context Protocol (MCP).
- Package: `mcpshld` (v1.0.11 on npm) with CLI bin `mcp-shield` and `mcpshld`.
- Tech Stack: TypeScript, Node.js, Tree-sitter AST, eBPF SIMD fastpath, FPE bijective DLP, WORM cryptographic audit.
- Web Platform & Console: Next.js 16 (App Router), React 19, Tailwind CSS v4, Recharts, Lucide Icons, Supabase SSR & Auth.
- Telemetry: Real-time HMAC-SHA256 signed ingestion (`/api/v1/telemetry/ingest`), threat stream, guardrail metrics.

## Completed Milestones
- Enterprise Marketing Website (`/`): Interactive Zero-Day Attack Simulator, copyable config for Claude/Cursor/Antigravity, JSON-LD SEO, sitemap.xml.
- Console & Telemetry Center (`/console`):
  - Connection health indicator (🟢 Live / 8s Polling / ⚪ Demo Mode) with real-time freshness ticker.
  - Onboarding Checklist Banner & 4-step interactive Onboarding Wizard (`OnboardingWizard.tsx`).
  - Workspace/Organization Switcher (`WorkspaceSwitcher.tsx`) with role and tier badges.
  - Click-to-inspect Threat Event Detail Drawer (`EventDetailDrawer.tsx`) with AST analysis, payload viewer, and allowlist creation.
  - Comprehensive filters: Environment (Prod/Staging/Dev), Date Range (1h/24h/7d/30d), Action Type, and Search.
  - Multi-select bulk actions: Bulk acknowledge and CSV export.
  - Metric calculation tooltips explaining Attacks Neutralized, AST latency, and Secrets Tokenized.
- Enterprise Settings Suite (`/settings`):
  - General: Key management table with prefixes, rotation, revocation, expiry, and reveal-once modal.
  - Security: Device/session management, 2FA/MFA setup, IP allowlisting, and Enterprise SAML/OIDC SSO.
  - Team: Organization members and role-based permissions (Owner, Admin, Member).
  - Billing: Unified Stripe (Global USD) and Razorpay (India INR) checkout, seat usage meter, invoice history, and cancellation flow.
  - Integrations: Outbound JSON-RPC / SIEM webhooks, Slack/Teams alerts, PagerDuty integration.
  - Audit Logs: Privileged organization action logs with CSV export.
- Compliance & Trust Center:
  - `/compliance`: SOC 2 Type II audit-evidence export, Zero Customer Payload Storage guarantee, encryption specs, data residency.
  - `/privacy`, `/terms`, `/security`, `/subprocessors`: Complete legal and security disclosure framework.
- Security Invariants & Cross-System Hardening:
  - Canonical ApiKey contract shared across CLI, Next.js API, and Database.
  - Zero development fallback in production mode; strict HMAC & SHA-256 validation.
  - CLI `link` performs signed cryptographic handshake with `/api/v1/telemetry/verify` before confirming pairing.
  - Telemetry strictly decoupled from MCP hot path with durable local disk spool (`~/.mcp-shield/spool/`), backpressure cap, and graceful shutdown flushing.
  - Complete multi-tenant runtime identity (`installation_id`, `environment`, `sequence_number`, `eventId` deduplication).
  - Pre-serialization telemetry sanitization scrubbing filesystem paths and credentials.
  - Synchronized event taxonomy: BLOCK, SANITIZE, QUARANTINE, RATE_LIMIT, PASSTHROUGH, PROMPT, ERROR across UI, API, DB.
- Verification & Deployment:
  - 41/41 test suites passed (683/683 unit & integration tests).
  - Remediation milestone: Fixed MCP initialization race, tools/call vs call_tool secret restoration, outbound DLP (result/error/params), loopback dashboard binding, TOCTOU COW verification, and dispatcher concurrency.
  - Published as `mcpshld@1.0.13` on npm.
  - Pushed to GitHub (PR #16 created for branch protection compliance).

