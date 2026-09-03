# MCP Shield Cloud Console & Marketing Platform

Production Next.js 16 web platform, interactive attack simulator, real-time threat telemetry console, and key pairing hub for Model Context Protocol (MCP) and AI Agents.

## Tech Stack
- **Framework**: Next.js 16 (App Router), React 19, Tailwind CSS v4
- **Visualizations**: Recharts dynamic area and bar charts
- **Auth & Database**: Supabase SSR (`@supabase/ssr`), PostgreSQL RLS
- **Billing**: Stripe subscription checkout & webhook integration
- **Telemetry**: Real-time HMAC-SHA256 ingestion pipeline (`/api/v1/telemetry/ingest`)

## Key Pages & Routes
- `/`: Enterprise landing page, SEO metadata, interactive zero-day attack simulator, client setup tabs
- `/console`: Authenticated real-time threat console, 24h evaluation timeline, vector breakdown, API key center
- `/guide`: Complete user guide with master key activation, configuration snippets for Claude, Cursor, Antigravity, Cline, Windsurf
- `/settings/billing`: Subscription plans, Pro upgrade, quota management
- `/api/v1/telemetry/stats`: 24-hour timeline aggregations and attack vector categorization
- `/api/v1/telemetry/events`: Paginated, filterable security events
- `/api/v1/keys`: Cryptographically secure client API key generation with configurable expiration (30d, 60d, 90d, 1y)

## Local Development
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the application.

## Production Build
```bash
npm run build
```
