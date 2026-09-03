# Production Deployment & Setup Guide (100% Free Tier)

This guide provides step-by-step instructions to deploy the MCP Shield marketing website, the authenticated `/console` telemetry dashboard, and connect your local AI agents (Claude Desktop, Cursor, Antigravity) using exclusively free-tier services.

---

## Architecture Overview

```
                        +----------------------------+
                        |  AI Agent (Claude/Cursor)  |
                        +--------------+-------------+
                                       |
                              (npx mcp-shield proxy)
                                       v
                        +----------------------------+
                        |   MCP Shield Local Proxy   |
                        | (AST, Bijective DLP, SSRF) |
                        +--------------+-------------+
                                       |
                     HMAC-SHA256 Signed Telemetry (JSON-RPC)
                                       v
      +------------------------------------------------------------------+
      |               Vercel (Free Serverless / Edge)                    |
      |   - Landing Page (SEO / Metadata / Schema.org)                   |
      |   - Interactive Security Attack Simulator                        |
      |   - Ingest API: /api/v1/telemetry/ingest                         |
      |   - Authenticated Console: /console                              |
      +--------------------------------+---------------------------------+
                                       |
                                       v
                 +---------------------------------------------+
                 |          Supabase (Free Tier Postgres)      |
                 |   - Auth (GitHub OAuth & Magic Links)       |
                 |   - Tables: security_events, api_keys       |
                 +---------------------------------------------+
```

---

## Step 1: GitHub Repository Setup (Free)

1. Create a free GitHub repository (e.g. `https://github.com/<your-username>/mcp-shield`).
2. Commit and push your codebase:
   ```bash
   git add .
   git commit -m "feat: complete production website, console, and telemetry pipeline"
   git remote add origin https://github.com/<your-username>/mcp-shield.git
   git branch -M main
   git push -u origin main
   ```

---

## Step 2: Supabase Setup (Free Tier Database & Auth)

1. Go to [database.new](https://database.new) and sign in for free.
2. Create a new project (e.g., `mcp-shield-prod`).
3. Open the **SQL Editor** and run the database migration:
   - Navigate to `supabase/migrations/20260901_mcp_shield_dashboard.sql` in this repository and paste the contents into the Supabase SQL editor.
4. Go to **Project Settings -> API** and copy:
   - `Project URL` -> `NEXT_PUBLIC_SUPABASE_URL`
   - `anon public key` -> `NEXT_PUBLIC_SUPABASE_ANON_KEY`
5. (Optional) Go to **Authentication -> Providers -> GitHub** to enable one-click GitHub login.

---

## Step 3: Vercel Deployment (Free Tier Hosting & Edge API)

1. Go to [vercel.com](https://vercel.com) and log in with your GitHub account.
2. Click **Add New Project** and select your `mcp-shield` repository.
3. In **Root Directory**, select `cloud-dashboard`.
4. Add the following Environment Variables:
   - `NEXT_PUBLIC_SUPABASE_URL`: `https://your-project.supabase.co`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`: `your-anon-key`
   - `MCP_SHIELD_SHARED_KEY`: `your-random-32-char-secret-key`
   - `NEXT_PUBLIC_APP_URL`: `https://your-app.vercel.app` (or your custom domain)
5. Click **Deploy**. Vercel will build and deploy the application with free SSL, automatic edge CDN caching, and serverless functions in ~45 seconds.

---

## Step 4: Render (Optional Free Container Deployment)

If you wish to host an independent cloud proxy or persistent container runner on Render:
1. Go to [render.com](https://render.com) and create a free Web Service.
2. Connect your GitHub repository and select **Docker** as the environment.
3. Set the build command or rely on the root `Dockerfile`.
4. Deploy on the free instance type.

---

## Step 5: Connecting Your Local MCP Agent to the Live Console

Once your website is deployed (e.g. at `https://your-app.vercel.app`), connect your local agent:

1. **Activate Enterprise License**:
   ```bash
   mcpshld license <YOUR_LICENSE_KEY>
   ```

2. **Pair your local CLI**:
   ```bash
   npx -y mcpshld link --url "https://your-app.vercel.app/api/v1/telemetry/ingest" --key "mcp_live_sec_89b21a"
   ```

3. **Run a simulated attack batch to test live streaming**:
   ```bash
   MCP_SHIELD_CLOUD_URL="https://your-app.vercel.app/api/v1/telemetry/ingest" npm run telemetry:demo
   ```

4. **Configure Claude Desktop or Cursor** (`claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "shielded-filesystem": {
         "command": "npx",
         "args": [
           "-y",
           "mcpshld",
           "wrap",
           "--",
           "npx",
           "-y",
           "@modelcontextprotocol/server-filesystem",
           "/Users/username/Desktop"
         ],
         "env": {
           "MCP_SHIELD_API_KEY": "mcp_live_YOUR_KEY_HERE"
         }
       }
     }
   }
   ```

5. Open `https://your-app.vercel.app/console` to watch all attacks, blocks, and DLP tokenizations stream live with sub-millisecond metrics!
