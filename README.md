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
| 🌲 **AST Shell Parsing** | Employs `tree-sitter-bash` native C bindings to parse shell commands into Abstract Syntax Trees. Defeats syntactic evasions (`$IFS`, nested quotes, wrapper stacking `sudo env nice`, subshells `$()`, heredocs, pipelines, and fork bombs) with strict POSIX short-flag splitting (`-rf` vs `-exclude`). |
| 🔑 **Reversible DLP Secret Sanitizer** | Single-pass scanning with high-entropy tokenization (AWS, OpenAI, Anthropic, GitHub PATs, SSH keys) using zero-allocation buffers. Yields **100% Precision and 100% Recall** on labeled benchmarks with provably lossless roundtrip restoration. |
| 🌐 **DNS Rebinding & Egress Shield** | Validates network targets, performs active IP pinning, blocks SSRF to link-local/private ranges (RFC 1918, `169.254.169.254`, IPv6 `::1`), and enforces domain allowlists/blocklists. |
| 📂 **Copy-on-Write (COW) Staging** | Intercepts file writes and redirects modifications to an isolated staging directory (`.mcp-shield/cow`), generating diffs for operator review before committing to disk. |
| 📦 **Container Sandbox Isolation** | Automatically spawns untrusted MCP servers in ephemeral Docker containers with dropped capabilities (`--cap-drop=ALL`), `network=none`, and read-only root filesystems. |
| 🛡️ **Client Schema Drift Protection** | Pinned, CI-tested adapters for **Claude Desktop**, **Cursor IDE**, **Windsurf**, and **Cline** that guarantee safe wrapping across client updates with automatic rollback backups. |
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

MCP-Shield automatically discovers, validates schemas, and protects MCP configurations for **Claude Desktop**, **Cursor IDE**, **Cline (VS Code)**, and **Windsurf**:

```bash
mcp-shield protect
```

This validates client configuration schemas, creates timestamped backups, and wraps all defined MCP servers idempotently with `mcp-shield wrap`.

### 3. Manual Server Wrapping

You can manually protect any downstream MCP server by prefixing its launch command:

```bash
# Example: Securing the official filesystem MCP server
mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace

# Example: Securing a local Python MCP server
mcp-shield wrap -- python -m mcp_server_git
```

---

## ⚡ Performance & Empirical Accuracy

MCP-Shield is built for ultra-low latency and empirically proven security:

- **Hot-Path Interception Overhead**: `~ 150 µs` (p50 median) — adds `< 0.04%` latency to LLM tool calls
- **AST Parser Throughput**: `> 7,500 ops/sec` (< 130 µs per command)
- **DLP Sanitizer Accuracy**: **100% Precision / 100% Recall** across 1,780+ lines of test code and logs
- **DLP Scanner Speed**: `> 200,000 lines/sec` with pre-allocated zero-allocation entropy buffers
- **Rate Limiting & Policy Evaluation**: `< 5 µs` (> 200,000 ops/sec)

See [BENCHMARKS.md](BENCHMARKS.md) for reproducible benchmark runs, category breakdowns, and latency percentiles.

---

## 🎯 Red-Team, Bug Bounty & Security Audit

Security tools must be validated against hostile, adversarial pressure:

- 🛡️ **Independent Security Audit**: Read our full external assessment in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
- 📋 **Documented CVEs**: Review full writeups and patch histories in [SECURITY.md](SECURITY.md) (`CVE-2026-SHIELD-001`, `CVE-2026-SHIELD-002`, `CVE-2026-SHIELD-003`).
- 🎯 **Public Bypass Challenge**: Submit new bypass PoCs via the [Bypass Challenge Template](.github/ISSUE_TEMPLATE/security_bypass.yml).
- ⚠️ **Zero-Telemetry False Positive Reporting**: Report benign collisions via the [False Positive Template](.github/ISSUE_TEMPLATE/false_positive.yml).

```bash
# Run the adversarial bypass corpus regression suite
npx jest tests/security-corpus/bypass-corpus.test.ts

# Run fast-check property-based tests
npx jest tests/security-corpus/property-based.test.ts

# Run the complete test suite (480+ tests across 16 suites)
npm test
```

---

## 📚 Documentation Directory

- 📐 [Security Architecture](SECURITY_ARCHITECTURE.md) - Zero-trust design, fail-closed semantics, and proxy pipeline.
- 🛡️ [Security Audit Report](SECURITY_AUDIT.md) - Formal third-party security assessment and penetration test report.
- 🔒 [Security Policy & CVE Writeups](SECURITY.md) - Vulnerability disclosures, CVE writeups, and Security Hall of Fame.
- ⚡ [Performance & Accuracy Benchmarks](BENCHMARKS.md) - Verified latency percentiles and labeled DLP benchmarks.
- 🎯 [Threat Model](THREAT_MODEL.md) - Scope boundaries, attacker models, and mitigation matrices.
- 📊 [Control Matrix](CONTROL_MATRIX.md) - Mappings to OWASP LLM Top 10 and MITRE ATT&CK / ATLAS frameworks.
- 🧪 [Red-Team Program](REDTEAM.md) - Bypass challenge rules, test harnesses, and submission guidelines.
- 🤝 [Contributing Guide](CONTRIBUTING.md) - Development workflow, testing standards, and code quality expectations.
- 🚀 [Release Process](RELEASING.md) - Release cadence, versioning policy, and CI/CD publishing pipeline.
- 📖 [Additional Resources](ADDITIONAL.md) - Curated references, specifications, and AI security guides.
- 📜 [Code of Conduct](CODE_OF_CONDUCT.md) - Community participation standards.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
