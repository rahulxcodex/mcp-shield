# MCP Shield - Project Context

## Project Architecture
- Core: Zero-Trust Security Proxy & Gateway for Model Context Protocol (MCP) and AI Agents.
- Tech Stack: TypeScript, Node.js, Tree-sitter AST (Bash, PowerShell, Cmd, Python), eBPF SIMD fastpath, FPE bijective DLP, WORM cryptographic audit.
- Web Platform & Console: Next.js 16 (App Router), React 19, Tailwind CSS v4, Recharts, Lucide Icons, Supabase SSR & Auth.
- Telemetry: Real-time HMAC-signed ingestion (`/api/v1/telemetry/ingest`), threat stream, guardrail metrics.

## Completed Milestones
- Enterprise Marketing Website (`/`):
  - SEO optimized with OpenGraph, Twitter Cards, Schema.org JSON-LD (SoftwareApplication, FAQPage, WebSite), dynamic `robots.txt`, and `sitemap.xml`.
  - Interactive Zero-Day Attack Simulator with live AST verdict, latency stats, and payload preview.
  - Drop-in installation guides with copyable configurations for Claude Desktop, Cursor, Antigravity, VSCode Cline, and Python/TS SDKs.
  - Security comparison matrix and enterprise FAQ.
- Real-Time Console (`/console`):
  - Moved dashboard to `/console` with authentication check and demo/guest mode.
  - Recharts visualizations (24h threat interception area chart, attack vector bar chart).
  - Live intercept feed with category filtering, search, and "Simulate Live Attack" trigger.
  - SOC2 JSON/CSV audit report exporter.
- Telemetry Pipeline (`scripts/send-demo-telemetry.ts`):
  - Signed HMAC-SHA256 telemetry ingestion verified with live Next.js endpoint.
- Verification & Deployment:
  - Playwright E2E verification passed across landing page, simulator, console, sitemap, and robots.
  - Free-tier deployment instructions documented in `DEPLOYMENT_GUIDE.md` and complete documentation in `USER_GUIDE.md`.
  - Proxy Core Telemetry: Hooked `CloudTelemetryPublisher` into `ProxyServer.logAndBroadcast(...)` for live agent event streaming.
  - Console Key Center: Built interactive API key generation and device pairing center in `/console` with modal creation and `/api/v1/keys` endpoint.
  - Unique Key Lookup Prefix & Scoping:
  - Fixed P1 badge: Generated keys now store unique 8-character random hex prefixes (`mcp_live_${prefixId}`) and enforced `UNIQUE` constraint in database migration.
# MCP Shield - Project Context

## Project Architecture
- Core: Zero-Trust Security Proxy & Gateway for Model Context Protocol (MCP) and AI Agents.
- Tech Stack: TypeScript, Node.js, Tree-sitter AST (Bash, PowerShell, Cmd, Python), eBPF SIMD fastpath, FPE bijective DLP, WORM cryptographic audit.
- Web Platform & Console: Next.js 16 (App Router), React 19, Tailwind CSS v4, Recharts, Lucide Icons, Supabase SSR & Auth.
- Telemetry: Real-time HMAC-signed ingestion (`/api/v1/telemetry/ingest`), threat stream, guardrail metrics.

## Completed Milestones
- Enterprise Marketing Website (`/`):
  - SEO optimized with OpenGraph, Twitter Cards, Schema.org JSON-LD (SoftwareApplication, FAQPage, WebSite), dynamic `robots.txt`, and `sitemap.xml`.
  - Interactive Zero-Day Attack Simulator with live AST verdict, latency stats, and payload preview.
  - Drop-in installation guides with copyable configurations for Claude Desktop, Cursor, Antigravity, VSCode Cline, and Python/TS SDKs.
  - Security comparison matrix and enterprise FAQ.
- Real-Time Console (`/console`):
  - Moved dashboard to `/console` with authentication check and demo/guest mode.
  - Recharts visualizations (24h threat interception area chart, attack vector bar chart).
  - Live intercept feed with category filtering, search, and "Simulate Live Attack" trigger.
  - SOC2 JSON/CSV audit report exporter.
- Telemetry Pipeline (`scripts/send-demo-telemetry.ts`):
  - Signed HMAC-SHA256 telemetry ingestion verified with live Next.js endpoint.
- Verification & Deployment:
  - Playwright E2E verification passed across landing page, simulator, console, sitemap, and robots.
  - Free-tier deployment instructions documented in `DEPLOYMENT_GUIDE.md` and complete documentation in `USER_GUIDE.md`.
  - Proxy Core Telemetry: Hooked `CloudTelemetryPublisher` into `ProxyServer.logAndBroadcast(...)` for live agent event streaming.
  - Console Key Center: Built interactive API key generation and device pairing center in `/console` with modal creation and `/api/v1/keys` endpoint.
  - Unique Key Lookup Prefix & Scoping:
  - Fixed P1 badge: Generated keys now store unique 8-character random hex prefixes (`mcp_live_${prefixId}`) and enforced `UNIQUE` constraint in database migration.
  - Scoped key queries and deletions strictly to user's organization projects.
  - Telemetry ingest now returns HTTP 500 on database insertion failures and enforces strict HMAC verification.
- Website User Guide & Security Hardening:
  - Sanitized `/guide` and all markdown documentation: Completely stripped internal CEO master key (`MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY`) and replaced with `<YOUR_LICENSE_KEY>` and instructions to obtain license via Console / GitHub auth.
  - Added dedicated "Sign In" button in desktop navbar and mobile navigation pointing directly to `/login`.
  - Allowed public route access to `/guide` in middleware.
  - Created `scripts/sanity-check-website.ts` executing 7/7 automated Playwright sanity checks (zero master key leaks, navbar auth navigation, login button, guide accessibility, attack simulator, console telemetry, and dynamic SEO).
  - Verified 100% passing E2E with both `verify-website.ts` and `sanity-check-website.ts`.
