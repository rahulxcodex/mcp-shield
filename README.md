# 🛡️ MCP-SHIELD

> **The Zero-Trust Security Gateway, AST Firewall & Secret Sanitizer for Model Context Protocol (MCP) and AI Agents.**

[![CI](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml)

With the rapid adoption of Claude Desktop, Cursor, Cline, and Windsurf, the **Model Context Protocol (MCP)** has become the standard connecting LLMs to local developer environments. But granting an AI agent raw host privileges exposes you to Prompt Injections, Destructive Commands (`rm -rf`), and Secret Exfiltration.

**`mcp-shield`** sits as a transparent, ultra-low-latency wire proxy between your AI IDE and the underlying MCP server. It analyzes the JSON-RPC streams in real-time, blocking malicious actions before they ever reach your OS.

## ✨ Features

- **Tree-Sitter AST Command Firewall:** Parses shell commands into a Concrete Syntax Tree. It actively detects and blocks subshells `$(...)`, absolute pipe-to-interpreter bypasses (`curl | /bin/bash`), and destructive recursive deletions (`rm -rf /`).
- **Bijective Secret Sanitizer (DLP):** Intercepts AWS keys, GitHub PATs, and SSH private keys outputted by your tools. Replaces them with UUID-based tokens (`[[SHIELD_SECRET_...]]`) before they reach the LLM, and reconstitutes them on the way back down.
- **Shannon Entropy Analysis:** Detects and masks high-entropy unstructured secrets (e.g. base64 passwords).
- **Shadow Copy-on-Write (COW) Virtual FS:** Safely intercepts AI file modifications (`write_file`), stages them in a `.mcp-shield/cow` sandbox, and generates colored diffs.
- **Human-in-the-Loop TUI Bridge:** A beautiful `Ink`-based terminal UI that renders approval modals (Approve / Reject) directly to `process.stderr` without corrupting the JSON-RPC streams.
- **Auto-Discovery Configuration:** Instantly protect Claude Desktop, Cursor, Cline, and Windsurf with a single command.

## 🚀 Quick Start

### 1. Auto-Protect Your IDEs
Run the auto-discovery script to automatically patch your MCP client configurations (Claude, Cursor, Cline, Windsurf) to wrap your existing servers with `mcp-shield`.

```bash
npx mcp-shield protect
```

### 2. Manual Wrapper
You can wrap any downstream MCP server manually by prefixing it:

```bash
npx mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace
```

## ⚙️ Configuration

`mcp-shield` relies on a declarative YAML policy engine. By default, it generates `shield.config.default.yaml`. 
The policy engine supports **hot-reloading**, so changes to this file take effect immediately!

```yaml
version: "1.0"
profile: "developer"

redaction:
  enabled: true
  maskStyle: "synthetic"
  highEntropyCheck: true
  entropyThreshold: 4.2

rules:
  - id: "block-destructive-rm"
    name: "Block Recursive Root Deletion"
    targetTools: ["*bash*", "*terminal*", "*exec*"]
    riskLevel: "CRITICAL"
    action: "block"
```

## 🏗️ Architecture
`mcp-shield` is built for **microsecond latency**. It uses a zero-copy *Vectored Buffer Queue* for JSON-RPC chunk framing, relying on C++ SIMD optimized `Buffer.indexOf` to scan for boundaries, avoiding massive memory GC spikes in Node.js.

## 🔒 Threat Model Defenses
- **TV-02: Indirect Prompt Injection (IPI)** -> Isolated context boundaries.
- **TV-04: Arbitrary Shell Evasion** -> `tree-sitter-bash` AST evaluation.
- **TV-05: Credential Harvesting** -> Bijective Secret Redaction + Shannon Entropy checks.
