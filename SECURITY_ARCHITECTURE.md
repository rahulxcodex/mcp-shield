# MCP-Shield Security Architecture 📐

> **Zero-Trust Wire Gateway & Defense-in-Depth Specification for Model Context Protocol (MCP) Interception.**

---

## 🏛️ Core Architectural Tenets

MCP-Shield operates on a **Zero-Trust Architecture** designed specifically for autonomous AI agents, developer IDEs, and Model Context Protocol (MCP) tooling.

1. **Deny-by-Default / Allowlist-First**: Tools, file paths, environment variables, and outbound egress domains are untrusted and blocked unless explicitly authorized by policy.
2. **Capability-Based Authorization**: Rather than inspecting raw tool names in isolation, tools are categorized into semantic security capabilities (`filesystemRead`, `filesystemWrite`, `shellExecution`, `networkEgress`, `credentialAccess`).
3. **AST-Level Syntax Analysis over Naive Regex**: Shell commands are parsed into Concrete Syntax Trees via `tree-sitter-bash` to eliminate lexical obfuscation, alias encapsulation, parameter expansions, and wrapper nesting.
4. **Bijective Session Tokenization**: Secrets and API keys are dynamically detected via Shannon entropy and regex signatures, scrubbed on outbound streams, replaced with UUID tokens, and bijectively restored on return traffic.
5. **Fail-Closed Resilience**: Any unexpected failure in the security evaluation pipeline (parser crash, schema desynchronization, network timeout, payload corruption) triggers an immediate `BLOCK` or `QUARANTINE`.
6. **Cryptographic Audit Integrity**: Every intercepted event is chained with SHA-256 / HMAC-SHA-256 hashes to guarantee tamper evidence.

---

## 🗺️ High-Level System Architecture

```
                      ┌─────────────────────────────────┐
                      │    AI Client (Claude / Cursor)  │
                      └────────────────┬────────────────┘
                                       │ stdio JSON-RPC
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MCP-SHIELD GATEWAY                               │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. JsonRpcStreamFramer: Chunk defragmentation & 10MB DoS bounds     │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Framed Messages                      │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │ 2. SecretSanitizer & Vault: Bijective Tokenization (DLP)            │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Redacted Payloads                    │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │ 3. RateLimiter: Sliding-window frequency throttling per tool        │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Passed Rate Check                    │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │ 4. PolicyEngine Priority Ladder                                     │   │
│   │    - Path Normalization (relative, Windows, traverse ../)           │   │
│   │    - ASTAnalyzer (tree-sitter-bash wrapper unwinding & fuzzer rules)│   │
│   │    - NetworkProxy (DNS Pinning & SSRF / Private IP filtering)       │   │
│   └─────────────────┬─────────────────┬───────────────────┬─────────────┘   │
│                     │                 │                   │                 │
│                 [ALLOW]           [SANDBOX]           [QUARANTINE / BLOCK]  │
│                     │                 │                   │                 │
│                     ▼                 ▼                   ▼                 │
│         ┌───────────────────────┐ ┌───────────────┐ ┌───────────────────┐   │
│         │ Direct Downstream MCP │ │ Docker / COW  │ │ Return JSON-RPC   │   │
│         │ Server Execution      │ │ Isolation     │ │ Error to Client   │   │
│         └───────────┬───────────┘ └───────┬───────┘ └─────────┬─────────┘   │
│                     │                     │                   │             │
│   ┌─────────────────▼─────────────────────▼───────────────────▼─────────┐   │
│   │ 5. SessionLogger: Append-only HMAC-SHA-256 Hash Chain (.jsonl)      │   │
│   ├─────────────────────────────────────────────────────────────────────┤   │
│   │ 6. DashboardServer: WebSockets Live Telemetry (localhost:3333)       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Component Breakdown & Security Mechanics

### 1. JSON-RPC Stream Framing (`src/core/stream-framing.ts`)
- Implements bounded buffer stream framing for stdio JSON-RPC streams.
- Handles partial chunk fragmentation, Windows CRLF (`\r\n`) and Unix LF (`\n`) newlines.
- Enforces an upper limit of **10 MB per frame** to defeat memory exhaustion / Denial of Service.
- Validates UTF-8 multi-byte sequence alignment across split chunks.

### 2. Secret Sanitizer & Vault (`src/security/sanitizer.ts`, `src/security/vault.ts`)
- **Bijective Tokenization**: Matches high-entropy strings and credentials (AWS access keys, OpenAI `sk-proj-*`, Anthropic `sk-ant-*`, GitHub PATs `ghp_*`, SSH private keys, GCP service accounts) and replaces them with unique tokens: `[[SHIELD_SECRET_xxxxxxxx]]`.
- **Bidirectional Restoration**: When the downstream server responds or when tools return sanitized parameters, the proxy accurately restores original values without corrupting payload structure.
- **Honey-Token Detection**: Actively alerts and quarantines processes attempting to read decoy canary tokens (`MCP_SHIELD_HONEY_TOKENS`).

### 3. AST Command Firewall (`src/security/ast-analyzer.ts`)
- Uses `tree-sitter-bash` native C bindings to parse POSIX shell commands into an Abstract Syntax Tree.
- **Grammar & Platform Scope**:
  - **POSIX Shells (`bash`, `sh`, `zsh`)**: Full Abstract Syntax Tree traversal and node normalization.
  - **Windows Shells (`cmd.exe`, `powershell`)**: Lexical argument tokenization, parameter switch parsing (`/s`, `/q`, `-Recurse`), and path switch disambiguation (`/src` vs `/s`).
- **Wrapper Unwinding**: Recursively resolves and unwinds execution wrappers:
  `sudo`, `env`, `nohup`, `nice`, `stdbuf`, `timeout`, `su`, `doas`, `strace`, `ltrace`, `pkexec`, `time`.
- **Evasion Defenses**:
  - Delimiter and expansion tricks: `$IFS`, `${VAR:-...}`, dynamic variable execution (`$CMD`).
  - Redirections & Heredocs: `bash <<< "..."`, `sh < /tmp/x.sh`, process substitutions `<(...)`.
  - Dangerous builtins & subshells: `$()`, backticks, `eval`, `source`, `exec`.
  - Destructive primitives: `rm -rf /`, `rm -rf *`, `mkfs.*`, `dd if=/dev/...`, `shred`, fork bombs (`:(){ :|:& };:`).

### 4. Policy Engine (`src/security/policy-engine.ts`)
- Evaluates tool invocations against declarative rules loaded from YAML (`shield.config.default.yaml`).
- **Priority Ladder**:
  $$\text{QUARANTINE} \gg \text{BLOCK} \gg \text{PROMPT} \gg \text{SANDBOX} \gg \text{ALLOW}$$
- **Path Normalization**: Resolves traversal segments (`../`), Windows backslashes (`C:\`), uppercase variations (`/ETC/passwd`), and relative paths without leading slashes.

### 5. DNS Rebinding & Egress Network Shield (`src/security/network-proxy.ts`)
- **DNS Resolution Pinning**: Resolves domain names to IP addresses prior to outbound connection to defeat time-of-check to time-of-use (TOCTOU) DNS rebinding.
- **Private & Link-Local IP Filtering**: Strictly blocks SSRF targeting RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 loopback (`::1`, `fc00::/7`, `fe80::/10`), and cloud metadata (`169.254.169.254`).
- **Domain Pattern Matcher**: Enforces domain wildcards (`*.ngrok.io`, `*.evil.com`).

### 6. Copy-on-Write (COW) Staging Sandbox (`src/sandbox/cow-fs.ts`)
- Intercepts file mutation tool calls (`write_file`, `edit_file`, `patch_file`).
- Stages modified contents in an isolated workspace cache (`.mcp-shield/cow`).
- Generates standard unified diffs comparing staged changes against original files, requiring operator confirmation before atomic commit.

### 7. Container Sandbox Isolation (`src/sandbox/container-sandbox.ts`)
- For untrusted MCP servers requiring arbitrary execution, spawns child containers with:
  - `--network=none` (Network cutoff)
  - `--read-only` (Read-only root filesystem)
  - `--cap-drop=ALL` (Drop all kernel capabilities)
  - `--security-opt=no-new-privileges`
  - Strict memory and CPU bounds (`--memory=512m`)

### 8. Clean Environment Stripping (`src/core/proxy.ts`)
- Strips high-risk environment variables before launching downstream processes:
  - Cloud credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`.
  - API keys: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `SLACK_TOKEN`.
  - Binary/Library hijacking: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `NODE_OPTIONS`, `BASH_ENV`, `PYTHONPATH`.
- Preserves essential OS variables (`PATH`, `HOME`, `SYSTEMROOT`, `TEMP`).

### 9. Tamper-Evident Audit Trail (`src/audit/session-logger.ts`, `src/cli/commands/replay.ts`)
- Logs every decision in append-only JSONL format.
- Computes cryptographic hash chains:
  $$H_0 = \text{GENESIS}$$
  $$H_n = \text{HMAC-SHA256}(H_{n-1} \parallel \text{CanonicalJSON}(\text{Data}_n), K_{\text{audit}})$$
- Includes monotonic sequence numbers (`seq: 0, 1, 2, ...`) to prevent log entry deletion or reordering.

---

## 🔒 Fail-Closed Security Guarantees

| Failure Mode | Gateway Behavior | Security Impact |
| :--- | :--- | :--- |
| **AST Parser Timeout (> 64KB input)** | Immediate `BLOCK` | Prevents regex DoS & CPU exhaustion |
| **Malformed JSON-RPC Stream** | Reset frame buffer, emit error | Prevents stream injection |
| **Unresolved Domain / DNS Failure** | Immediate `BLOCK` | Prevents outbound SSRF |
| **Policy Engine Exception** | Defaults to `BLOCK` | Eliminates bypasses from malformed rule structures |
| **Child Process Abrupt Crash** | Gateway exits with matching exit code | Prevents orphaned ghost processes |
