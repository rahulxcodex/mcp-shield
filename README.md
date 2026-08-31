# MCP-Shield 🛡️

[![CI](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B%20%7C%2020%2B%20%7C%2022%2B-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Security: Zero--Trust](https://img.shields.io/badge/Security-Zero--Trust-red.svg)](SECURITY_ARCHITECTURE.md)

> **The Zero-Trust Security Gateway, AST Shell Firewall & Secret Sanitizer for the Model Context Protocol (MCP) and Autonomous AI Agents.**

---

## 📖 Overview

With the rapid adoption of AI coding assistants and autonomous agents in tools like **Claude Desktop**, **Cursor IDE**, **Windsurf**, **Cline**, and **Zed**, granting LLMs unrestricted host execution privileges introduces severe security vulnerabilities:

- **OS Command Injection & Destructive Deletions**: Unchecked shell tool calls (`rm -rf`, disk overwrites, fork bombs).
- **Credential & API Key Exfiltration**: Prompt injection leaking environment variables, cloud keys (AWS, GCP, GitHub PATs), and SSH keys.
- **Egress Exfiltration & DNS Rebinding**: Unauthorized outbound HTTP/TCP requests targeting internal networks, metadata services (`169.254.169.254`), or attacker webhooks.
- **Runaway Tool-Calling Loops**: Infinite retry loops consuming excessive tokens and compute resources.
- **Direct Filesystem Tampering**: Silent file modifications outside the active workspace.

**MCP-Shield** sits directly on the wire as a transparent JSON-RPC stdio proxy between your AI client and downstream MCP servers. It intercepts every tool invocation and applies real-time AST parsing, high-entropy secret tokenization, rate limiting, and sandbox isolation before any command touches your OS.

```
┌────────────────────────────────────────────────────────┐
│               AI Client / IDE Host                    │
│   (Claude Desktop, Cursor, Windsurf, Cline, Zed)      │
└──────────────────────────┬─────────────────────────────┘
                           │ JSON-RPC (stdio)
                           ▼
┌────────────────────────────────────────────────────────┐
│                   MCP-SHIELD GATEWAY                   │
│  ┌──────────────────────┬───────────────────────────┐  │
│  │ 📦 Stream Framer     │ 🔑 Secret Vault & DLP     │  │
│  ├──────────────────────┼───────────────────────────┤  │
│  │ 🌲 AST Shell Firewall│ 🚦 Sliding-Window Rate    │  │
│  ├──────────────────────┼───────────────────────────┤  │
│  │ 🌐 DNS/Egress Filter │ 🛡️ Policy Engine (YAML)   │  │
│  ├──────────────────────┼───────────────────────────┤  │
│  │ 📜 Tamper-Proof Audit│ 📊 Real-Time Web Monitor  │  │
│  └──────────────────────┴───────────────────────────┘  │
└──────────────────────────┬─────────────────────────────┘
                           │ Sanitized & Verified Calls
                           ▼
┌────────────────────────────────────────────────────────┐
│               Downstream MCP Server                    │
│     (Filesystem, Terminal, GitHub, Postgres, etc.)     │
└────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

| Capability | Description |
| :--- | :--- |
| 🌲 **AST Shell Parsing** | Employs `tree-sitter-bash` to parse shell commands into an Abstract Syntax Tree. Defeats syntactic evasions (`$IFS`, nested quotes, wrapper stacking `sudo env nice`, subshells `$()`, heredocs, pipelines, and fork bombs). |
| 🔑 **Bijective Secret Sanitizer (DLP)** | Scans inbound and outbound JSON-RPC payloads for high-entropy secrets (AWS, OpenAI, Anthropic, GitHub PATs, SSH keys) and replaces them with session-scoped tokens that restore safely on response. |
| 🌐 **DNS Rebinding & Egress Shield** | Validates network targets, performs active IP pinning, blocks SSRF to link-local/private ranges (RFC 1918, `169.254.169.254`, IPv6 `::1`), and enforces domain allowlists/blocklists. |
| 📂 **Copy-on-Write (COW) Staging** | Intercepts file writes and redirects modifications to an isolated staging directory (`.mcp-shield/cow`), generating diffs for operator review before committing to disk. |
| 📦 **Container Sandbox Isolation** | Automatically spawns untrusted MCP servers in ephemeral Docker containers with dropped capabilities (`--cap-drop=ALL`), `network=none`, and read-only root filesystems. |
| 🧹 **Safe Environment Stripping** | Sanitizes child process environment variables, stripping cloud credentials, shell injection vectors (`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`), while preserving essential POSIX/Windows runtime variables. |
| 🚦 **Sliding-Window Rate Limiting** | Throttles runaway autonomous loops per tool and across the global session. |
| 📜 **Tamper-Evident Audit Logging** | Records cryptographically chained logs (SHA-256 / HMAC-SHA-256) with sequence numbers to detect tampering or log deletion. |
| 📊 **Real-Time Web Dashboard** | Embedded Express & WebSocket dashboard at `http://localhost:3333` for live telemetry, attack visualization, and policy management. |

---

## 🚀 Quick Start

### 1. Installation

Install MCP-Shield globally or use it via `npx`:

```bash
# Global installation via npm
npm install -g mcp-shield

# Or run directly with npx
npx mcp-shield --help
```

### 2. Auto-Discover & Protect Your IDEs

MCP-Shield can automatically discover and protect existing MCP configurations for **Claude Desktop**, **Cursor IDE**, **Cline (VS Code)**, and **Windsurf**:

```bash
mcp-shield protect
```

This scans your configuration files, creates timestamped backups, and wraps all defined MCP servers with `mcp-shield wrap`.

### 3. Manual Server Wrapping

You can manually protect any downstream MCP server by prefixing its launch command:

```bash
# Example: Securing the official filesystem MCP server
mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace

# Example: Securing a local Python MCP server
mcp-shield wrap -- python -m mcp_server_git
```

---

## 💻 CLI Commands

MCP-Shield provides a complete command-line interface:

```bash
🛡️  MCP-SHIELD
Usage:
  mcp-shield install              Quickly install and configure MCP-Shield.
  mcp-shield scan                 Scan your MCP servers for security vulnerabilities.
  mcp-shield fix                  Automatically generate and apply security policies.
  mcp-shield protect              Auto-discover and protect MCP clients.
  mcp-shield replay <log_file>    Replay and verify tamper-evident audit logs.
  mcp-shield wrap -- <cmd> [args] Wrap an MCP server with the security gateway.
```

### Command Highlights

- **`mcp-shield scan`**: Analyzes configured MCP servers and tool definitions, highlighting credential exposure, dangerous shell capabilities, and unrestricted file access.
- **`mcp-shield fix`**: Interactively generates strict policy rules tailored to your environment and upgrades your security posture.
- **`mcp-shield replay <log_file>`**: Replays intercepted session logs, verifies cryptographic hash chains, and flags any tampered or missing entries.

---

## ⚙️ Configuration

MCP-Shield is configured via a declarative YAML file (`shield.config.default.yaml` or `.mcp-shield/config.yaml`):

```yaml
version: "1.0"
profile: "default"

redaction:
  enabled: true
  maskStyle: "token"
  highEntropyCheck: true
  entropyThreshold: 4.5

sandbox:
  cowEnabled: true
  cowStagingDir: ".mcp-shield/cow"
  autoCommitOnApproval: true

egress:
  enabled: true
  blockedDomains:
    - "*.ngrok.io"
    - "*.evil.com"

audit:
  enabled: true
  logDir: ".mcp-shield/logs"
  tamperEvidentHashing: true

rules:
  - id: "allow-all-safe"
    name: "Allow safe commands"
    priority: 10
    riskLevel: "LOW"
    action: "allow"
    
  - id: "block-destructive-rm"
    name: "Block Recursive Root Deletion"
    priority: 100
    targetTools:
      - "*bash*"
      - "*terminal*"
      - "*exec*"
    riskLevel: "CRITICAL"
    action: "block"
```

---

## ⚡ Performance & Benchmarks

MCP-Shield is built for ultra-low latency, sitting on the hot path of every tool call:

- **Hot-Path Interception Overhead**: `< 0.2 ms` (p50 median)
- **AST Parser Throughput**: `> 7,700 ops/sec` (< 130 µs per command)
- **Rate Limiting & Policy Evaluation**: `< 10 µs` (> 100,000 ops/sec)
- **DLP Sanitization**: `> 140,000 ops/sec` for standard tool payloads

See [BENCHMARKS.md](BENCHMARKS.md) for full reproducible latency percentiles and test environment specifications.

---

## 🎯 Red-Team & Adversarial Hardening

MCP-Shield includes an automated adversarial test harness and red-team challenge suite to defend against sophisticated evasion techniques:

```bash
# Run the automated red-team bypass test suite
npm run test:redteam

# Run the randomized AST fuzzer (thousands of mutations)
npm run fuzz

# Run the complete test suite (470+ tests across 14 suites)
npm test
```

Read [REDTEAM.md](REDTEAM.md) for details on our open security research program and how to submit reproducible bypasses.

---

## 📚 Documentation Directory

- 📐 [Security Architecture](SECURITY_ARCHITECTURE.md) - Deep dive into zero-trust design, fail-closed semantics, and proxy pipeline.
- 🎯 [Threat Model](THREAT_MODEL.md) - Scope boundaries, attacker models, and mitigation matrices.
- 📊 [Control Matrix](CONTROL_MATRIX.md) - Mappings to OWASP LLM Top 10 and MITRE ATT&CK / ATLAS frameworks.
- ⚡ [Performance Benchmarks](BENCHMARKS.md) - Verified latency percentiles and benchmark scripts.
- 🧪 [Red-Team Program](REDTEAM.md) - Rules of engagement, testing harnesses, and submission guidelines.
- 🤝 [Contributing Guide](CONTRIBUTING.md) - Development workflow, testing standards, and code quality expectations.
- 🚀 [Release Process](RELEASING.md) - Release cadence, versioning policy, and CI/CD publishing pipeline.
- 🔒 [Security Policy](SECURITY.md) - Vulnerability reporting and responsible disclosure.
- 📖 [Additional Resources](ADDITIONAL.md) - Curated references, specifications, and AI security guides.
- 📜 [Code of Conduct](CODE_OF_CONDUCT.md) - Community participation standards.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
