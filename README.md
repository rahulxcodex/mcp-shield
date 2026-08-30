# 🛡️ MCP-SHIELD: Complete Architecture, Security Specification & Implementation Blueprint

> **Tagline:** *The Zero-Trust Security Gateway, AST Firewall & Secret Sanitizer for Model Context Protocol (MCP) and AI Agents.*

---

## Table of Contents
1. [Executive Summary & The Core Problem](#1-executive-summary--the-core-problem)
2. [High-Level System Architecture](#2-high-level-system-architecture)
3. [Low-Level Systems Engineering (OS & IPC)](#3-low-level-systems-engineering-os--ipc)
4. [Cybersecurity Threat Model & Defense Mechanisms](#4-cybersecurity-threat-model--defense-mechanisms)
5. [Tree-Sitter AST & Command Firewall Engine](#5-tree-sitter-ast--command-firewall-engine)
6. [DLP, Secret Redactor & Honey-Token Engine](#6-dlp-secret-redactor--honey-token-engine)
7. [Shadow Copy-on-Write (COW) Virtual Filesystem](#7-shadow-copy-on-write-cow-virtual-filesystem)
8. [Developer Experience & Config Auto-Discovery](#8-developer-experience--config-auto-discovery)
9. [Declarative Policy Configuration (`shield.config.yaml`)](#9-declarative-policy-configuration-shieldconfigyaml)
10. [Phase-by-Phase MVP Development Roadmap](#10-phase-by-phase-mvp-development-roadmap)
11. [The Master Implementation Prompt](#11-the-master-implementation-prompt)
12. [Viral Launch Strategy & Open-Source Growth](#12-viral-launch-strategy--open-source-growth)

---

## 1. Executive Summary & The Core Problem

With the rapid adoption of **Claude Desktop, Cursor, Cline, Windsurf, Aider**, and autonomous AI agents, the **Model Context Protocol (MCP)** has become the universal standard connecting LLMs to local developer environments (terminals, filesystems, databases, APIs).

### The Security Vulnerabilities in Vanilla MCP:
1. **Raw Host Privileges**: MCP servers run directly in the developer’s user context with access to SSH keys, cloud credentials, and OS shells.
2. **Indirect Prompt Injections & Tool Poisoning**: An agent reading an untrusted web page, issue tracker, or codebase README can be hijacked by hidden instructions to execute destructive actions (`rm -rf`, `DROP TABLE`) or exfiltrate sensitive files.
3. **Data Leaks & Context Window Bloat**: Sensitive environment variables (`.env`, `id_rsa`, AWS tokens) are frequently ingested into the prompt context, leaking secrets to third-party LLM providers.
4. **Green Test Theater & Unchecked File Overwrites**: Agents overwrite codebase files blindly without providing visual diffs or transactional rollback capabilities.

**`mcp-shield`** solves these acute friction points by providing a zero-config, ultra-low-latency (< 1.5ms overhead) transparent wire proxy, AST command firewall, bijective secret sanitizer, and Copy-On-Write sandbox.

---

## 2. High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AI Host Client (Claude, Cursor, Cline)                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ JSON-RPC 2.0 (stdio / SSE / Sockets)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MCP-SHIELD ENGINE                                   │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 1. Transparent Wire Interceptor (< 1.5ms overhead, stdio / SSE)       │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ 2. Tree-Sitter AST Analyzer (POSIX & PowerShell command parser        │  │
│  │    blocks 'rm -rf /', subshells '$()', reverse shells, and pipe-to-sh)│  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ 3. DLP & Bijective Secret Redactor (Masks AWS, GitHub, OpenAI keys    │  │
│  │    with synthetic tokens and reconstitutes them on return)            │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ 4. Shadow Copy-on-Write (COW) Virtual FS & Git Diff Sandbox           │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ 5. Ratatui / Ink TUI Approval Modal (Rendered strictly to /dev/tty)   │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │ Sanitized, Permitted Execution
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               Target MCP Servers (Filesystem, Terminal, Postgres, GitHub)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Low-Level Systems Engineering (OS & IPC)

### 3.1 Transport Modes
- **Stdio Transparent Pipe (`mcp-shield wrap -- <command> [args]`)**: Spawns target MCP server as a controlled child process. Intercepts host `stdin` -> proxy -> child `stdin` and child `stdout` -> proxy -> host `stdout`. Child `stderr` is passed untouched.
- **SSE / HTTP Reverse Proxy (`mcp-shield proxy --listen 127.0.0.1:8765 --upstream http://localhost:3000/sse`)**: Termination proxy parsing incoming chunked Server-Sent Events and JSON-RPC POST payloads.
- **IPC Daemon Multiplexer (Unix Domain Sockets / Windows Named Pipes)**: Central background daemon mode allowing multiple IDE sessions to route through a single hardened instance.

### 3.2 Microsecond Latency Budget (Target: < 1.5ms)
- Stream Ingestion: Zero-copy framing with uninitialized spare capacity buffer (< 8 µs).
- JSON-RPC Framing: SIMD line break & header scan (`memchr`) (< 5 µs).
- AST & Policy Check: Tree-sitter incremental parsing + compiled Aho-Corasick tables (< 35 µs).
- In-Flight Overhead: ~75 µs in Rust native core / ~1.2ms in Node.js streaming core.

### 3.3 Process Supervision & Clean Teardown
- **Unix**: Subprocess PID groups with `setpgid(0, 0)` and graceful shutdown via `SIGINT` -> `SIGTERM` -> `SIGKILL`.
- **Windows**: Child processes assigned to an anonymous Win32 **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` preventing orphan processes.

---

## 4. Cybersecurity Threat Model & Defense Mechanisms

| Vector ID | Attack Name | Mechanics & Attack Surface | `mcp-shield` Defense |
| :--- | :--- | :--- | :--- |
| **TV-01** | **Tool Poisoning & Schema Injection** | Malicious MCP server injects adversarial instructions into tool schemas (`tools/list`). | Schema integrity validation & prompt delimiter scrubbing. |
| **TV-02** | **Indirect Prompt Injection (IPI)** | Attacker embeds prompt overrides in untrusted HTML, PDFs, or git commits. | Context boundary isolation, HTML comment stripping, zero-width char scrubber. |
| **TV-03** | **Confused Deputy Escalation** | Low-privilege data triggers high-privilege execution (e.g. web fetch -> `execute_command`). | AST semantic command firewall & strict binary allowlists. |
| **TV-04** | **Arbitrary Code Execution & Shell Evasion**| Exploiting CLI tools with shell tricks (`$IFS`, `base64`, subshells `$()`, pipe-to-sh). | Tree-sitter AST syntax decomposition and subshell bans. |
| **TV-05** | **Credential Harvesting & Exfiltration** | Agent scans default credential locations (`~/.ssh`, `.env`) and leaks secrets. | Bijective secret sanitizer + decoy honey-token tripwires. |
| **TV-06** | **Symlink Escape & TOCTOU Traversal** | Manipulating filesystem tools using race conditions and directory symlink swapping. | Path canonicalization + file descriptor pinning (`O_NOFOLLOW`). |

---

## 5. Tree-Sitter AST & Command Firewall Engine

Regex-based blacklists (`/rm -rf/`, `/curl/`) fail against basic shell obfuscation (e.g. `c'a't /et'c'/pa'ss'wd`, `cat$IFS/etc/passwd`, `echo bHMgLWxh | base64 -d | sh`, `$(printf '\x72\x6d') -rf /`).

`mcp-shield` parses commands into a full Concrete Syntax Tree (CST) using `tree-sitter-bash` and verifies:
- **Destructive Deletion Patterns**: Flags `rm -rf /`, `rm -rf ~`, `rm -rf *`, wildcard root deletions.
- **Pipe-to-Interpreter Checks**: Disallows piping data directly into interpreters (`curl ... | bash`, `wget ... | sh`).
- **Dynamic Subshells & Process Substitutions**: Flags suspicious `$()`, `` ` `` and `<()` constructs.
- **Unauthorized Binary Invocations**: Enforces a strict allowlist of allowed binaries (`git`, `npm`, `cargo`, `pytest`, `tsc`).

---

## 6. DLP, Secret Redactor & Honey-Token Engine

Data Loss Prevention operates bidirectionally across all JSON-RPC message streams:

```
Tool Output / File Stream
  │
  ├─► [1. Pattern Engine] Matches AWS (AKIA...), GitHub (ghp_...), OpenAI/Anthropic keys, SSH Private Keys
  │
  ├─► [2. Shannon Entropy] Flags unstructured secrets (> 4.2 bits/byte on 20+ char strings)
  │
  ├─► [3. Bijective De-masker] Replaces actual secrets with synthetic tokens:
  │     `sk-proj-94812...` ──► `SHIELD_SECRET_1` (sent to LLM)
  │     `SHIELD_SECRET_1`  ──► `sk-proj-94812...` (reconstituted on return to tool)
  │
  └─► [4. Honey-Tokens] Injects decoy credentials; triggers instant session quarantine if touched
```

---

## 7. Shadow Copy-on-Write (COW) Virtual Filesystem

When an AI agent modifies codebase files (`write_file`, `edit_file`, `replace_file`):
1. Writes are diverted to an ephemeral staging directory (`.mcp-shield/cow/<session-id>/`).
2. A unified, colorized git diff is generated comparing the staged version against disk.
3. The diff is presented to the user in the TUI for single-key approval (`[y] Approve / [n] Reject`).
4. On approval, the file is atomically committed to disk; on rejection, the staging cache is discarded.

---

## 8. Developer Experience & Config Auto-Discovery

### 8.1 1-Line Execution
```bash
# Wrap any command on the fly:
npx mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace
```

### 8.2 1-Click Multi-Client Auto-Discovery
`npx mcp-shield protect` automatically discovers, creates a timestamped backup, and injects `mcp-shield` into:
- **Claude Desktop**: `claude_desktop_config.json`
- **Cursor IDE**: `~/.cursor/mcp.json`
- **Cline (VS Code)**: `cline_mcp_settings.json`
- **Windsurf**: `mcp_config.json`

---

## 9. Declarative Policy Configuration (`shield.config.yaml`)

```yaml
version: "1.0"
profile: "developer"

redaction:
  enabled: true
  maskStyle: "synthetic"
  highEntropyCheck: true
  entropyThreshold: 4.2

sandbox:
  cowEnabled: true
  cowStagingDir: ".mcp-shield/cow"
  autoCommitOnApproval: false

rules:
  # Block destructive filesystem deletion
  - id: "block-destructive-rm"
    name: "Block Recursive Root Deletion"
    targetTools: ["*bash*", "*terminal*", "*exec*", "*filesystem*"]
    riskLevel: "CRITICAL"
    action: "block"
    matchers:
      astRules:
        disallowedCommands: ["rm -rf /", "rm -rf /*", "rm -rf ~", "rm -rf ."]

  # Intercept arbitrary command execution
  - id: "prompt-arbitrary-exec"
    name: "Prompt User on Shell Execution"
    targetTools: ["*bash*", "*shell*", "*terminal*", "*execute_command*"]
    riskLevel: "HIGH"
    action: "prompt"

  # Sandbox file writes
  - id: "sandbox-file-writes"
    name: "Sandbox and Diff File Writes"
    targetTools: ["*write_file*", "*edit_file*", "*replace_file*"]
    riskLevel: "MEDIUM"
    action: "sandbox"

  # Deny reading sensitive credential files
  - id: "deny-credentials-read"
    name: "Deny Access to Credential Files"
    targetTools: ["*read_file*", "*filesystem*"]
    riskLevel: "CRITICAL"
    action: "block"
    matchers:
      pathMatches:
        forbiddenPaths:
          - "**/.env*"
          - "**/id_rsa*"
          - "**/.aws/credentials"
          - "**/.ssh/*"
          - "**/secrets.yaml"

audit:
  enabled: true
  logDir: "~/.mcp-shield/logs"
  tamperProofHashing: true
```

---

## 10. Phase-by-Phase MVP Development Roadmap

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                                MVP DEVELOPMENT TIMELINE                               │
├─────────────────────────┬─────────────────────────────┬───────────────────────────────┤
│   PHASE 1 (Weeks 1-2)   │     PHASE 2 (Weeks 3-4)     │      PHASE 3 (Weeks 5-6)      │
│  Wire Proxy & Redactor  │  AST Policy & Terminal TUI  │  Shadow COW & Client Ecosystem│
├─────────────────────────┼─────────────────────────────┼───────────────────────────────┤
│ • Stdio JSON-RPC stream │ • Tree-sitter Shell AST     │ • Ephemeral COW Sandbox       │
│ • Aho-Corasick + Regex  │ • Declarative YAML Engine   │ • 1-Click Multi-client Inject │
│ • Bidirectional token   │ • Ink / React Terminal TUI  │ • Tamper-evident Audit Logs   │
│   redaction & de-mask   │ • Risk Tiering Heuristics   │ • Session Replay Engine       │
│ • < 2ms latency engine  │ • Real-time Prompt Approval │ • CI/CD Headless Gate Mode    │
└─────────────────────────┴─────────────────────────────┴───────────────────────────────┘
```

---

## 11. The Master Implementation Prompt

```markdown
You are an expert Systems & Cyber Security Architect specializing in Node.js/TypeScript, AST parsing, and the Model Context Protocol (MCP). Your objective is to build `mcp-shield` — an ultra-low-latency, zero-trust security gateway and AST firewall for MCP servers and AI agents.

### 1. Core Responsibilities & Features to Implement:
1. **Transparent Stdio Wire Proxy (`src/core/proxy.ts`)**:
   - Spawn target MCP server subprocess inheriting env vars (`spawn(cmd, args, { stdio: ['pipe', 'pipe', process.stderr] })`).
   - Parse inbound/outbound JSON-RPC 2.0 messages with a streaming chunk/line-framing engine.
   - Forward signals (SIGINT, SIGTERM) and propagate child exit codes gracefully.

2. **DLP & Bijective Secret Sanitizer (`src/security/sanitizer.ts`)**:
   - Detect AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), OpenAI/Anthropic keys (`sk-...`), and private RSA/SSH keys.
   - Maintain a bidirectional mapping: replace sensitive keys with synthetic identifiers (`SHIELD_SECRET_1`) before sending to the LLM, and reconstitute them when returned in tool parameters.

3. **Tree-Sitter Shell AST Analyzer (`src/security/ast-analyzer.ts`)**:
   - Parse shell commands targeting terminal tools (`execute_command`, `bash`, `run_terminal_cmd`).
   - Block or escalate: recursive root deletions (`rm -rf /`, `rm -rf ~`), wildcard destructions, reverse shells (`nc -e`, `bash -i >& /dev/tcp`), subshell evaluations (`$()`, `` ` ``), process substitutions (`<()`), and pipes to interpreters (`curl ... | sh`).

4. **Shadow Copy-on-Write (COW) Virtual FS (`src/sandbox/cow-fs.ts`)**:
   - Stage file mutations (`write_file`, `edit_file`) into an ephemeral directory (`.mcp-shield/cow/<session-id>/`).
   - Generate colored unified diffs for terminal preview before atomic commits.

5. **Terminal TUI Human-in-the-Loop Bridge (`src/tui/prompt-bridge.ts`)**:
   - Render high-contrast approval modals exclusively to `process.stderr` / `/dev/tty` so JSON-RPC stdio pipes are never corrupted.
   - Single-key actions: `[y] Approve`, `[n] Reject (returns JSON-RPC -32000 error)`, `[a] Always Allow Session`, `[s] Run in COW Sandbox`.

6. **1-Click Config Auto-Discovery (`src/cli/commands/protect.ts`)**:
   - Auto-discover, backup, and patch config files for Claude Desktop (`claude_desktop_config.json`), Cursor (`~/.cursor/mcp.json`), Cline (`cline_mcp_settings.json`), and Windsurf.

### 2. Project Directory Structure:
```
mcp-shield/
├── package.json
├── tsconfig.json
├── shield.config.default.yaml
├── bin/mcp-shield.js
├── src/
│   ├── index.ts
│   ├── cli/ (wrap, protect, unprotect, audit, replay)
│   ├── core/ (proxy, stream-framing, jsonrpc)
│   ├── security/ (sanitizer, ast-analyzer, policy-engine, patterns)
│   ├── sandbox/ (cow-fs, diff-viewer)
│   ├── tui/ (prompt-bridge, App.tsx)
│   ├── adapters/ (claude-desktop, cursor, cline, windsurf)
│   └── audit/ (session-logger, replay-engine)
└── tests/
    ├── unit/ (framing, sanitizer, ast-analyzer, policy)
    ├── integration/ (proxy-flow, cow-fs)
    └── fixtures/ (dummy-mcp-server.js)
```

### 3. Verification Criteria:
- Pass all unit tests covering AST shell evasion attempts, fragmented JSON buffers, and secret redaction.
- Run integration tests with `dummy-mcp-server.js` verifying that `rm -rf /` is blocked with 0 execution and file writes create COW diffs.
- Total proxy latency overhead must remain under 2ms per message.

Begin building the project structure and implementation immediately.
```

---

## 12. Viral Launch Strategy & Open-Source Growth

1. **The 15-Second Demo Video**:
   - Show Claude 3.7 attempting a prompt-injected `rm -rf /` or reading `.env`.
   - Show `mcp-shield` intercepting it in real time with a cyberpunk red terminal alert and sanitized output.
2. **Show HN Script**: Positioning as *"Zero-Trust Wireshark & AST Firewall for Claude Desktop, Cursor, and Cline"*.
3. **Repository Badge Growth Loop**:
   - Provide a `[![Secured by MCP-Shield](https://img.shields.io/badge/MCP--Shield-Protected-brightgreen)](https://github.com/mcp-shield/mcp-shield)` badge for MCP server creators.
