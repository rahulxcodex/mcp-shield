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
  - Render Keep-Alive: Added `.github/workflows/render-keepalive.yml` pinging free-tier instances every 10 mins.
  - Vercel Live Deployment: Deployed to `https://mcp-shield-dashboard-d6jyrwkny-rahulsahgupta24-8925.vercel.app`.
  - GitHub Integration: Pushed `feat/console-keys-telemetry-guide` and opened PR #11 on `rahulxcodex/mcp-shield`.
