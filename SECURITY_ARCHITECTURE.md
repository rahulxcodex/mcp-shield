# MCP-Shield Security Architecture 📐

> **Zero-Trust Wire Gateway & Defense-in-Depth Specification for Model Context Protocol (MCP) Interception.**

---

## 🏛️ Core Architectural Tenets

MCP-Shield operates on a **Zero-Trust Architecture** designed specifically for autonomous AI agents, developer IDEs, and Model Context Protocol (MCP) tooling.

1. **Deny-by-Default / Safe Network Defaults**: Tools, file paths, environment variables, private RFC 1918/4193 networks, link-local endpoints, and cloud metadata are untrusted and blocked by default.
2. **Schema-First Capability Inference**: Tools are categorized into semantic security capabilities (`filesystemRead`, `filesystemWrite`, `shellExecution`, `networkAccess`, `processSpawn`, `destructiveOperation`, `secretAccess`) by inspecting JSON Schema parameter names and formats before falling back to tool names or descriptions.
3. **AST-Level Syntax Analysis over Naive Regex**: Shell commands are parsed into Concrete Syntax Trees via `tree-sitter-bash` to eliminate lexical obfuscation, alias encapsulation, parameter expansions, and wrapper nesting.
4. **Bijective Session Tokenization & Granular Restoration**: Credentials are dynamically masked on outbound streams and stored in an ephemeral AES-256-GCM vault. Restoration occurs **only** for `TRUSTED` servers possessing declared `secretAccess` capabilities.
5. **Multi-IP DNS Rebinding & Dual-Stack Pinning**: Resolves all A and AAAA records across IPv4 and IPv6, evaluates every resolved address against egress policy, normalizes IPv4-mapped IPv6 literals (`::ffff:127.0.0.1`), and pins connections to verified IPs.
6. **Explicit Pipeline Representations**: Maintains strict separation between `RawSecurityInput` (evaluated by security engines), `SanitizedLogContextInput` (used for logs and TUI prompts), and `RestoredExecutionInput` (selectively forwarded downstream).
7. **Fail-Closed Resilience**: Any unexpected failure in the security evaluation pipeline (parser crash, schema desynchronization, network timeout, payload corruption) triggers an immediate `BLOCK` or `QUARANTINE`.
8. **Cryptographic Audit Integrity**: Every intercepted event is chained with SHA-256 / HMAC-SHA-256 hashes to guarantee tamper evidence.

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
│   │ 2. Pipeline Representation Split:                                   │   │
│   │    - RawSecurityInput (for AST, Egress, Policy Checks)              │   │
│   │    - SanitizedLogContextInput (for Logs, Dashboard, PromptBridge)   │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │                                      │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │ 3. RateLimiter: Sliding-window frequency throttling per tool        │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Passed Rate Check                    │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │ 4. Formalized 5-Phase Policy Engine Hierarchy:                      │   │
│   │    - Phase 1: Critical Detectors (Honey Tokens, Rate, AST, SSRF)    │   │
│   │    - Phase 2: Schema-First Capability & Attestation Validation      │   │
│   │    - Phase 3: Tool-Specific Rules & Path Matchers                   │   │
│   │    - Phase 4: Risk Escalation & Suspicious Attestation Sandboxing   │   │
│   │    - Phase 5: Default Fail-Closed Fallback                          │   │
│   └─────────────────┬─────────────────┬───────────────────┬─────────────┘   │
│                     │                 │                   │                 │
│                 [ALLOW]           [SANDBOX]           [QUARANTINE / BLOCK]  │
│                     │                 │                   │                 │
│                     ▼                 ▼                   ▼                 │
│         ┌───────────────────────┐ ┌───────────────┐ ┌───────────────────┐   │
│         │ 5. Granular Vault     │ │ Docker / COW  │ │ Return JSON-RPC   │   │
│         │ Restoration & Child   │ │ Staging       │ │ Error to Client   │   │
│         │ Execution             │ │ Boundary      │ │                   │   │
│         └───────────┬───────────┘ └───────┬───────┘ └─────────┬─────────┘   │
│                     │                     │                   │             │
│   ┌─────────────────▼─────────────────────▼───────────────────▼─────────┐   │
│   │ 6. SessionLogger: Append-only HMAC-SHA-256 Hash Chain (.jsonl)      │   │
│   ├─────────────────────────────────────────────────────────────────────┤   │
│   │ 7. DashboardServer: WebSockets Live Telemetry (localhost:3333)       │   │
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

### 2. Secret Sanitizer & Ephemeral Vault (`src/security/sanitizer.ts`, `src/security/vault.ts`)
- **Bijective Tokenization**: Matches high-entropy strings and credentials (AWS access keys, OpenAI `sk-proj-*`, Anthropic `sk-ant-*`, GitHub PATs `ghp_*`, SSH private keys, GCP service accounts) and replaces them with unique tokens: `[[SHIELD_SECRET_xxxxxxxx]]`.
- **False-Positive Suppression**: Automatically suppresses false-positive matches on UUIDs (`8-4-4-4-12`), pure hex SHA-256/MD5/Git hashes, and minified identifiers unless accompanied by explicit credential context.
- **Granular Restoration Policy**:
  - `UNTRUSTED` servers: Secrets are **never restored** (tokens retained).
  - `SUSPICIOUS` servers (capability mismatch): Secrets are **never restored**.
  - `TRUSTED` servers: Secrets are restored **only if** the tool explicitly declares or possesses the `secretAccess` capability.
- **Honey-Token Detection**: Actively alerts and quarantines processes attempting to read decoy canary tokens (`MCP_SHIELD_HONEY_TOKENS`).

### 3. Schema-First Capability Inference (`src/security/capabilities.ts`)
- Evaluates tool safety by prioritizing JSON Schema argument definitions over easily spoofed tool names:
  - `shellExecution`: schema properties named `command`, `cmd`, `script`, `bash`, `code`, `exec_command`.
  - `filesystemWrite`: schema properties named `content`, `text`, `patch`, `write_path`, `destination`, `overwrite`.
  - `filesystemRead`: schema properties named `path`, `file`, `filepath`, `dir`, `directory`, or `format: "path"`.
  - `networkAccess`: schema properties named `url`, `uri`, `endpoint`, `domain`, `host`, or `format: "uri"`.
  - `secretAccess`: schema properties named `api_key`, `secret`, `token`, `password`, `credential`.
- Deceptive tools (e.g. `calculate_metrics` taking a `command` string) are accurately flagged and subjected to AST firewall rules.

### 4. AST Command Firewall (`src/security/ast-analyzer.ts`, `src/security/powershell-analyzer.ts`, `src/security/cmd-analyzer.ts`)
- **Multi-Dialect Semantic Analysis**:
  - **POSIX Shells (`bash`, `sh`, `zsh`)**: Full Concrete Syntax Tree compilation via `tree-sitter-bash` native C bindings, evaluating pipelines, subshells, and command substitutions.
  - **PowerShell (`pwsh`, `powershell.exe`)**: Dedicated AST parser (`PowerShellASTAnalyzer`) implementing pipeline construction, scriptblock extraction, cmdlet alias canonicalization (`del`, `rm`, `ri`, `irm`, `iwr`, `saps`, `gc`, `sc`), parameter prefix resolution (`-r`, `-rec`, `-fo`, `-Confirm:$false`), base64 UTF-16LE / UTF-8 recursive unrolling (`-EncodedCommand`), and sensitive `$env:*` leakage protection.
  - **Windows Command Prompt (`cmd.exe`)**: Dedicated semantic parser (`CmdAnalyzer`) de-obfuscating caret escapes (`^`), quote slicing, compound chaining (`&`, `&&`, `||`, `|`), delayed expansion (`!VAR!`), wrapper unwrapping (`cmd /c`), and destructive system primitives (`vssadmin delete shadows`, `bcdedit`, `del /s /q`).
- **Wrapper Unwinding**: Recursively resolves and unwinds execution wrappers:
  `sudo`, `env`, `nohup`, `nice`, `stdbuf`, `timeout`, `su`, `doas`, `strace`, `ltrace`, `pkexec`, `time`, `cmd.exe /c`, `powershell.exe -Command`.
- **Evasion Defenses**:
  - Delimiter and expansion tricks: `$IFS`, `${VAR:-...}`, dynamic variable execution (`$CMD`, `& $cmd`, `!CMD!`).
  - Redirections & Heredocs: `bash <<< "..."`, `sh < /tmp/x.sh`, process substitutions `<(...)`, `Out-File`.
  - Dangerous builtins & subshells: `$()`, backticks, `eval`, `source`, `exec`, `Invoke-Expression` (`iex`), dynamic .NET reflection (`[System.Diagnostics.Process]::Start`).
  - Destructive primitives: `rm -rf /`, `Remove-Item -Recurse C:\`, `del /s /q C:\`, `vssadmin delete shadows`, `mkfs.*`, `dd if=/dev/...`, `shred`, fork bombs (`:(){ :|:& };:`).

### 5. Multi-IP DNS Rebinding & Egress Network Shield (`src/security/network-proxy.ts`, `src/security/ip-utils.ts`)
- **Centralized CIDR & Numerical Masking**: Parses IPv4 and IPv6 addresses into numerical BigInts to perform exact CIDR subnet matches across Loopback (`127.0.0.0/8`, `::1`), Link-Local (`169.254.0.0/16`, `fe80::/10`), Cloud Metadata (`169.254.169.254`, `fd00:ec2::254`), and Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `100.64.0.0/10`).
- **IPv4-Mapped IPv6 Normalization**: Normalizes `::ffff:127.0.0.1` and `0:0:0:0:0:ffff:...` to the underlying IPv4 address before policy evaluation.
- **Multi-Address Resolution Verification**: Queries all resolved A and AAAA records (`dns.lookup(host, { all: true })`). If **any** resolved IP violates egress policy, the entire request is rejected (defeating DNS round-robin / rebinding attacks).
- **IP Pinning**: Connects directly to the verified resolved IP while preserving the original `Host` header for virtual hosting.

### 6. Isolation Boundaries: Container Sandboxing vs. COW Filesystem Layer
- **Container Sandbox (`src/sandbox/container-sandbox.ts`)**:
  - Isolates the host OS, environment, and network (`--network=none`, `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, CPU/PID limits).
  - The workspace volume mount (`/workspace:rw` or `:ro`) provides developer repository access.
- **Copy-on-Write (COW) Staging Sandbox (`src/sandbox/cow-fs.ts`)**:
  - The COW layer serves as the designated security boundary for workspace mutations.
  - Intercepts file mutation tool calls (`write_file`, `edit_file`, `patch_file`).
  - Stages modified contents in `.mcp-shield/cow` and generates unified diffs for human operator review prior to atomic commit.

### 7. Tamper-Evident Audit Trail (`src/audit/session-logger.ts`, `src/cli/commands/replay.ts`)
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
| **Any Multi-IP DNS Address Forbidden** | Immediate `BLOCK` | Prevents DNS rebinding and dual-stack bypasses |
| **Policy Engine Exception** | Defaults to `BLOCK` | Eliminates bypasses from malformed rule structures |
| **Child Process Abrupt Crash** | Gateway exits with matching exit code | Prevents orphaned ghost processes |
