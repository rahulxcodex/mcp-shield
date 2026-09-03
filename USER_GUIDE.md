# MCP Shield — Complete User & Administrator Guide

Welcome to **MCP Shield**, the zero-trust runtime firewall and security gateway engineered specifically for the Model Context Protocol (MCP) and autonomous AI agent workflows (Claude Desktop, Cursor, Antigravity, VSCode Cline, Windsurf, and custom SDK agents).

---

## Table of Contents
1. [Architecture & Threat Model](#1-architecture--threat-model)
2. [Quickstart in 60 Seconds](#2-quickstart-in-60-seconds)
3. [Client Configuration Guides](#3-client-configuration-guides)
   - [Claude Desktop](#claude-desktop)
   - [Cursor IDE](#cursor-ide)
   - [Google Antigravity](#google-antigravity)
   - [VSCode Cline & Windsurf](#vscode-cline--windsurf)
4. [Cloud Console & API Key Management](#4-cloud-console--api-key-management)
   - [Generating API Keys](#generating-api-keys)
   - [Pairing Local Agents (`mcp-shield link`)](#pairing-local-agents-mcp-shield-link)
   - [Real-Time Threat Center & Interceptions](#real-time-threat-center--interceptions)
   - [Exporting SOC2 Type II Audit Logs](#exporting-soc2-type-ii-audit-logs)
5. [Security Features & Guardrails](#5-security-features--guardrails)
   - [Tree-sitter Abstract Syntax Tree (AST) Firewall](#tree-sitter-ast-firewall)
   - [SSRF & Cloud Metadata Protection](#ssrf--cloud-metadata-protection)
   - [Bijective Format-Preserving Encryption (FPE DLP)](#bijective-fpe-dlp)
   - [Canary Honeytokens](#canary-honeytokens)
   - [Copy-on-Write (COW) Filesystem Sandbox](#copy-on-write-cow-sandbox)
6. [Deployment Guide](#6-deployment-guide)
   - [Vercel Deployment (Dashboard & Web)](#vercel-deployment)
   - [Render Daemon Deployment & Free-Tier Keep-Alive](#render-daemon-deployment--keep-alive)
7. [CLI Reference](#7-cli-reference)

---

## 1. Architecture & Threat Model

MCP Shield acts as a non-invasive cryptographic proxy inserted between your AI host application (LLM orchestrator) and local or remote MCP servers.

```
┌─────────────────┐       JSON-RPC Stdio / SSE       ┌────────────────────────┐       Direct Process       ┌─────────────────┐
│  Host (Claude,  │ ───────────────────────────────> │       MCP SHIELD       │ ─────────────────────────> │  Target Server  │
│ Cursor, Agent)  │ <─────────────────────────────── │    Security Gateway    │ <───────────────────────── │  (e.g., SQLite, │
└─────────────────┘         Bidirectional AST        └───────────┬────────────┘       Strict Sandbox       │   Bash, Files)  │
                                Inspection                       │                                         └─────────────────┘
                                                                 │ HMAC-SHA256
                                                                 ▼
                                                     ┌────────────────────────┐
                                                     │  Cloud Console / SOC2  │
                                                     │   Threat Stream (Hub)  │
                                                     └────────────────────────┘
```

### Attack Vectors Neutralized
1. **Tool-Use Remote Code Execution (RCE)**: Destructive command chains (`rm -rf /`, encoded powershell strings, hidden semicolons/pipes) evaluated through Tree-sitter AST syntax trees before bash/cmd/terminal execution.
2. **SSRF & Cloud IMDS Exfiltration**: Blocks agent tool requests targeting `169.254.169.254`, `metadata.google.internal`, or localhost loopback interfaces.
3. **Prompt Injection Data Leaks**: High-entropy keys (AWS, OpenAI, Anthropic, Stripe, GitHub, Private Keys) are bijectively tokenized via DLP before reaching the model context.
4. **Agent Model Compromise (Canary Tripwires)**: Injects decoy honeytoken tools into the MCP catalog. If an exploited agent attempts to call a honeytoken, the session is quarantined immediately.

---

## 2. Quickstart in 60 Seconds

### Installation
You can install MCP Shield globally or run it directly using `npx`:

```bash
# Global installation (recommended)
npm install -g mcp-shield

# Verify installation
mcp-shield --version
```

### Enterprise Master License Activation
To unlock unlimited enterprise AST guardrails, bypass trial constraints, and activate full telemetry capabilities, run:

```bash
mcp-shield license MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY
```

This installs your authenticated enterprise license credential at `~/.mcp-shield/license.key` and activates all zero-trust subsystems permanently.

### Auto-Protecting Existing MCP Clients
Run the automated discovery engine to scan and protect all installed MCP clients on your machine:

```bash
mcp-shield protect
```
This automatically inspects configuration files for **Claude Desktop**, **Cursor**, **Cline**, and **Windsurf**, wrapping unshielded MCP servers inside `mcp-shield wrap` safely without breaking arguments or environment variables.

---

## 3. Client Configuration Guides

### Claude Desktop
Edit your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add `mcp-shield` in front of your server:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}
```

### Cursor IDE
Open `~/.cursor/mcp.json` or configure within **Cursor Settings > Features > MCP**:
```json
{
  "mcpServers": {
    "terminal-tools": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "node", "./mcp-server-terminal/dist/index.js"]
    }
  }
}
```

### Google Antigravity
In your workspace configuration or `.gemini/antigravity/mcp/` directory, register the shielded command:
```json
{
  "mcpServers": {
    "shielded-shell": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "mcp-server-commands"]
    }
  }
}
```

### VSCode Cline & Windsurf
- **Cline**: `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Windsurf**: `~/.codeium/windsurf/mcp_config.json`

Wrap any existing server with `mcp-shield wrap -- <command> <args...>`.

---

## 4. Cloud Console & API Key Management

### Generating API Keys
1. Navigate to your MCP Shield Cloud Console (`http://localhost:3000/console` or your deployed Vercel domain).
2. Under the **API Keys & Device Pairing** section in the right sidebar, click **"+ New Key"**.
3. Choose a key description (e.g. `MacBook Pro Cursor`) and client type.
4. Click **Generate Key**.
5. Copy the generated secret key (`mcp_live_sec_...`). This key is shown only once and authenticated via HMAC-SHA256 signatures.

### Pairing Local Agents (`mcp-shield link`)
To link your local CLI or development environment to the Cloud Console, execute:

```bash
mcp-shield link --key mcp_live_sec_your_secret_key_here
```

To pair with a custom or on-premise cloud endpoint:
```bash
mcp-shield link --key mcp_live_sec_your_key --url https://your-domain.com/api/v1/telemetry/ingest
```

This saves the configuration locally at `~/.mcp-shield/cloud.json`. Once linked, every tool execution, AST verdict, and DLP sanitization event streams directly into your console.

### Real-Time Threat Center & Interceptions
The `/console` interface displays:
- **Security Health Score (0-100)**: Real-time calculation based on incident frequency and policy posture.
- **24-Hour Threat Interception Timeline**: Live AreaChart displaying safe invocations vs. neutralized zero-day exploits.
- **Attack Vector Breakdown**: Categorization across AST injection, SSRF cloud metadata, DLP redacted secrets, and tripped canaries.
- **Live Intercept Stream**: Searchable, filterable event log showing timestamps, triggering detectors, and granular reasons.

### Exporting SOC2 Type II Audit Logs
Click the **Export SOC2 Log** button in the top right of `/console` to download an audit-ready JSON report containing:
- Criteria mappings (CC6.1, CC6.6, CC6.7)
- Cryptographic hash verification
- Aggregated health score and neutralized attacks
- Timestamped audit ledger of every tool evaluation

---

## 5. Security Features & Guardrails

### Tree-sitter AST Firewall
Unlike regex or pattern-matching firewalls, MCP Shield parses command lines into genuine Abstract Syntax Trees (ASTs) supporting Bash, PowerShell, Windows Command Prompt, and Python. It flags:
- Destructive commands (`rm -rf /`, `mkfs`, disk writes)
- Dangerous parameter combinations (`chmod 777`, `--no-preserve-root`)
- Evasion tricks (base64 encoded IEX executions, command chaining via semicolons, backticks, or subshells)

### SSRF & Cloud Metadata Protection
Prevents malicious agent payloads from accessing private metadata endpoints (AWS IMDS, GCP metadata, Azure instance metadata) and local intranet addresses (`127.0.0.1`, `localhost`, `10.0.0.0/8`, `192.168.0.0/16`).

### Bijective FPE DLP
Replaces sensitive credentials (API keys, JWTs, OAuth tokens, connection strings) with deterministic surrogate tokens. If the agent needs to re-use that secret in a trusted downstream tool call, MCP Shield securely restores the secret in-flight without exposing it to the LLM's prompt context.

### Canary Honeytokens
Spawns synthetic honeypot tools (e.g., `get_production_kubernetes_credentials`). Normal agent workflows will never trigger these tools. Any call instantly identifies prompt injection or model takeover and isolates the session.

### Copy-on-Write (COW) Sandbox
Filesystem modifications are initially applied to an isolated overlay buffer. Destructive or bulk file changes require explicit user confirmation before committing to host disk.

---

## 6. Deployment Guide

### Vercel Deployment
The marketing site, docs, and `/console` dashboard are built on Next.js 16 with React 19.

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```
2. Deploy the `cloud-dashboard` directory:
   ```bash
   cd cloud-dashboard
   vercel
   ```
3. Set environment variables in Vercel:
   - `NEXT_PUBLIC_SUPABASE_URL` (optional, for persistent multi-tenant DB)
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY` (optional)
   - `SUPABASE_SERVICE_ROLE_KEY` (optional)
   - `MCP_SHIELD_SHARED_KEY` (optional HMAC key)

### Render Daemon Deployment & Keep-Alive
If deploying a persistent background proxy daemon on Render's free tier:
- Render free instances spin down after 15 minutes of inactivity.
- MCP Shield provides a dedicated GitHub Actions workflow (`.github/workflows/render-keepalive.yml`) that pings your Render health endpoint every 10 minutes to maintain 100% uptime.

---

## 7. CLI Reference

| Command | Description |
| :--- | :--- |
| `mcp-shield protect` | Auto-detects and patches Claude, Cursor, Cline, and Windsurf configurations. |
| `mcp-shield license <key>` | Installs license credential (e.g. `MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY`). |
| `mcp-shield wrap -- <cmd> [args]` | Runs any MCP server inside the zero-trust security sandbox. |
| `mcp-shield link --key <key>` | Pairs local machine with Cloud Console for real-time telemetry. |
| `mcp-shield scan` | Audits installed MCP configurations for known CVEs and plaintext secrets. |
| `mcp-shield stats` | Shows local interception counts and security metrics. |
| `mcp-shield demo` | Spawns a local interactive sandbox to test AST and DLP attacks safely. |

---

*Need help or enterprise support? Visit [mcpshield.dev](https://mcpshield.dev) or inspect the repository at [github.com/rahulxcodex/mcp-shield](https://github.com/rahulxcodex/mcp-shield).*
