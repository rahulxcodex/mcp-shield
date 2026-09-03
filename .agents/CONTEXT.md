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
- Website User Guide (`/guide`):
  - Created interactive web user guide with Master License Activation (`MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY`), client tabs (Claude, Cursor, Antigravity, Cline, Windsurf), threat engine diagrams, and SOC2 walkthrough.
  - Verified with Playwright MCP testing on live deployment.
  - Render Keep-Alive: Added `.github/workflows/render-keepalive.yml` pinging free-tier instances every 10 mins.
  - Vercel Live Deployment: Deployed to `https://mcp-shield-dashboard-d6jyrwkny-rahulsahgupta24-8925.vercel.app` and preview `https://mcp-shield-dashboard-oqexrgwja-rahulsahgupta24-8925.vercel.app`.
  - GitHub Integration: Pushed `feat/console-keys-telemetry-guide` and opened PR #11 on `rahulxcodex/mcp-shield`.
- Production End-to-End Workflow & Licensing Pipeline:
  - Corrected NPM package naming from `mcp-shield` (unrelated third-party) to `mcpshld` (v1.0.9) with dual `mcpshld` / `mcp-shield` bin aliases.
  - Implemented dynamic telemetry aggregation endpoints (`/api/v1/telemetry/stats` and `/api/v1/telemetry/events`), replacing mock constants in Console Recharts with live database metrics.
  - Added API key expiration lifecycle (1-Month Free Trial / 30 Days default, 60d, 90d, 1y, continuous) and automatic expiration enforcement in telemetry ingestion.
  - Fixed Vercel deployment crash in `rahulxcodex/mcp-shield-licensing` by adding build-time fallback placeholders in `src/lib/supabase.ts`.
  - Configured 1-month trial duration (30 days) and 1-year GitHub account age gating in licensing API, supporting CEO master key `MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY`.
  - Verified 40/40 test suites passing (671/671 unit, integration, and red-team tests). Deployed live on Vercel (`READY`).
