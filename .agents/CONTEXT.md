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
  - Packaged as `mcpshld@1.0.12`.
- Console Navbar Redesign & Enterprise Admin Suite:
  - Decluttered navbar: 10 items → 4 (Logo+Workspace, Live indicator, More dropdown, Account dropdown).
  - `MoreDropdown.tsx`: Onboarding, Simulate, Export SOC2, Plans, Feedback, Theme Toggle in dropdown.
  - `AccountDropdown.tsx`: Role-aware profile dropdown with GitHub link, plan badge, admin panel links, sign out.
  - Dedicated Account section (`/settings/account`) with profile details, OAuth binding, quota meters, and password change.
  - Universal "Add Existing Key" flow with auto-elevation for `MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY`.
  - Enterprise Admin Panel (`/console/admin`): Key distribution pool, single email invite, CSV bulk mass invite, and join link generator.
  - Master Admin Panel (`/console/system-admin`): Multi-source telemetry tracking MCP, Dashboard, and Website metrics.
  - Multi-source analytics API (`/api/v1/admin/analytics`).
  - Middleware route guards: `/console/system-admin` → master admin only, `/console/admin` → enterprise + master.
  - Removed GitHub 1-year account age check from license API.
- Step 10 VRIO AI Agent Runtime Security Platform Milestone:
  - Step 1: Formal MCP protocol state machine (`src/core/mcp-protocol-state-machine.ts`) with fail-closed envelopes and initialize cancellation rejection.
  - Step 2: Proprietary Agent Attack Corpus (`src/security/attack-corpus.ts`) across 7 categories with complete reasoning chains and `mcp-shield attack-corpus` CLI.
  - Step 3: Security Intelligence Engine (`src/security/intelligence-engine.ts`) with unified capability graph, explainable risk scoring, and policy simulation.
  - Step 4: Standardized Security Benchmark (`benchmarks/mcp-security-benchmark.ts`) yielding 100/100 score and `mcp-shield benchmark` CLI.
  - Step 5: Multi-factor server identity fingerprinting, runtime drift detection (binary/schema/deps), and reputation graph (`src/security/server-identity.ts`).
  - Step 6: Ecosystem distribution auto-discovery covering Claude, Cursor, Windsurf, Cline, Zed, and Roo Code (`src/cli/commands/protect.ts`).
  - Step 7: Centralized Enterprise Control Plane APIs (`/api/v1/control-plane/policies`, `simulate`, `provenance`, `runtime`).
  - Step 8: IP Architecture & Trade Secret specification (`docs/IP_ARCHITECTURE.md`) with patent disclosure for Bijective Safe Secret Restoration.
  - Step 9: Independent trust verification suite (`scripts/verify-security-invariants.ts`) and reproducible test harness.
  - Step 10: Protocol-agnostic AI Agent Runtime Security Platform (`src/core/ai-runtime-security.ts`) & Console UI (`/console/ai-runtime`) for MCP, Coding Agents, Browser Agents, and Multi-Agent Swarms.
  - 42/42 test suites passing (691 tests).
  - Published `mcpshld@1.0.15` to npm.
