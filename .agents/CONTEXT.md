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
- Security Invariants (14/14):
  - SHA-256 hashed secret keys, constant-time HMAC comparison, rate-limiting, payment idempotency, CSRF protection, and fail-closed evaluation.
- Verification & Deployment:
  - 40/40 test suites passed (671/671 unit & integration tests).
  - 32/32 Next.js production routes compiled cleanly.
  - Published to npm (`mcpshld@1.0.11`) and deployed to GitHub & Vercel.
