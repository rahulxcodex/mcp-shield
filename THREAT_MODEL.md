# MCP-Shield Threat Model 🎯

> **Formal Threat Modeling, Trust Boundaries, and Security Assumptions for AI Agent Tool Gateways.**

---

## 📖 System Overview & Trust Assumptions

MCP-Shield operates as an inline security gateway between an AI Client / Host Environment (e.g., Claude Desktop, Cursor IDE, Windsurf) and downstream Model Context Protocol (MCP) servers.

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY A: AI Client / Developer Workspace               │
│ - Developer Prompts                                             │
│ - IDE Host Context                                              │
└───────────────────────────────┬─────────────────────────────────┘
                                │ (Untrusted Inputs / Tool Calls)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY B: MCP-Shield Gateway (Enforcement Zone)         │
│ - Stream Framer & Sanitizer                                     │
│ - Tree-Sitter AST Analyzer                                      │
│ - YAML Policy Engine & Egress DNS Pinning                       │
│ - Copy-on-Write Sandbox & Container Runtime Generator           │
│ - HMAC-SHA-256 Audit Trail                                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │ (Sanitized & Confirmed Invocations)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY C: Downstream MCP Servers & Target OS            │
│ - Filesystem MCP Server, Terminal MCP Server                    │
│ - Host OS Filesystem & Network Stack                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🦹 Threat Actors & Adversary Profiles

1. **Compromised / Jailbroken LLM (Indirect Prompt Injection)**:  
   An AI model executing malicious tool invocations induced by untrusted web pages, README files, or issues read into the model context.
2. **Malicious / Compromised MCP Server**:  
   A third-party MCP tool attempting to harvest environment variables, extract host credentials, or exfiltrate source code.
3. **Malicious Remote Infrastructure (C2)**:  
   External servers attempting DNS rebinding or receiving exfiltrated secrets over covert channels.
4. **Untrusted Workspace Repositories**:  
   Cloned codebases containing malicious subshell scripts or configuration files designed to exploit automated agent routines.

---

## 🛡️ STRIDE Threat Classification & Mitigations

| STRIDE Category | Threat Description | Attack Vector | MCP-Shield Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Downstream server claims unauthorized tool capabilities or spoofs JSON-RPC schema. | Dynamic capability escalation; schema poisoning. | **Schema Pinning & Capability Mapping**: Tool declarations are validated against strict profiles. |
| **Tampering** | Malicious agent attempts to overwrite system files or alter historical audit logs. | Arbitrary file writes; log deletion or hash alteration. | **COW Staging & Tamper-Proof Audit**: File writes staged in `.mcp-shield/cow`; logs chained via HMAC-SHA-256 with sequence counters. |
| **Repudiation** | Attacker executes destructive commands and denies action. | Unlogged subshell execution; erased history. | **Deterministic Session Logging**: Inbound and outbound JSON-RPC frames captured with timestamps and hashes in JSONL. |
| **Information Disclosure** | Agent leaks API keys, SSH private keys, or cloud credentials to model or external endpoints. | Cloud key extraction via environment variables or prompt output. | **Bijective Secret Sanitizer & Safe Env**: Replaces credentials with session tokens; strips environment variables before spawning. |
| **Denial of Service** | Autonomous agent trapped in infinite tool-calling loop or sending gigabyte JSON payloads. | High-frequency API calls; oversized stdio streams. | **Rate Limiter & Bounded Framer**: Sliding-window tool call throttling; 10 MB maximum frame size. |
| **Elevation of Privilege** | Agent breaks out of shell filters using wrappers (`sudo`, `env`) or inline subshells. | OS command injection (`rm -rf /`, `mkfs`, fork bombs). | **AST Shell Parser & Docker Sandbox**: Unwinds wrapper chains via `tree-sitter-bash`; runs untrusted code with `--cap-drop=ALL` and `--network=none`. |

---

## 🎯 In-Scope vs Out-of-Scope Boundaries

### ✅ In-Scope

- **Accidental & Adversarial OS Command Injection**: Defeating syntactic evasions (`$IFS`, nested quotes, dynamic variable execution, wrapper stacking).
- **Runaway Autonomous Loops**: Preventing runaway tool-calling recursion.
- **Credential & API Key Harvesting**: Redacting sensitive tokens (AWS, GCP, GitHub, OpenAI, Anthropic, SSH keys) across tool arguments and outputs.
- **Unauthorized Network Egress & DNS Rebinding**: Pinning DNS resolutions and blocking RFC 1918 / IPv6 private ranges and metadata endpoints (`169.254.169.254`).
- **Uncontrolled File Mutation**: Staging file modifications for review via Copy-on-Write.

### ❌ Out-of-Scope (Explicit Non-Goals & Architectural Boundaries)

To maintain credibility and avoid overpromising, MCP-Shield defines clear defensive boundaries:

1. **Pre-Compromised Host & Kernel Breakouts**:
   - If an adversary already has root or kernel-level privileges on the host before MCP-Shield starts, memory scraping, process injection, or proxy bypass cannot be prevented.
2. **Supply-Chain Compromises in Wrapped MCP Servers**:
   - MCP-Shield sits on the wire as a stream proxy. It does not perform static code analysis (SAST) on downstream server dependencies (e.g., malicious npm/pip packages executing native code during package install).
3. **Unwrapped Remote Network Transports (Raw SSE/TCP)**:
   - MCP-Shield enforces policy on local stdio JSON-RPC streams and child process invocations. If an MCP client connects directly to a remote MCP server over raw unintercepted network sockets without passing through the MCP-Shield proxy, it is outside the enforcement perimeter.
4. **Physical Access & Hardware Side-Channels**:
   - Hardware-level timing attacks, cold-boot memory extraction, or microarchitectural vulnerabilities (Spectre/Meltdown) are out of scope.
5. **Subjective Prompt Persuasion & Semantic Intent**:
   - MCP-Shield is an execution and data gateway enforcing deterministic syntactic rules, DLP redaction, and sandbox boundaries. It is not an LLM intent classifier and does not evaluate whether benign text is persuasive or manipulative.
6. **Windows Native PowerShell AST Grammar Parsing**:
   - Native C AST parsing is strictly implemented for POSIX shell grammar (`tree-sitter-bash`). On Windows, cmd.exe and PowerShell arguments are processed via lexical tokenization and switch parsers (`/s`, `/q`, `-Recurse`) rather than a full native PowerShell AST compiler.
7. **Environment-Variable Egress Enforcement Boundary**:
   - Network egress filtering operates as an environment-level proxy shim (`HTTP_PROXY` / `HTTPS_PROXY`). It provides domain policy and DNS-rebinding protection for standard HTTP/HTTPS SDKs. Downstream tools initiating raw TCP sockets or deliberately ignoring proxy environment variables bypass this shim unless Docker container network isolation (`network=none`) is enabled.
8. **In-Process Vault Encryption Key Storage**:
   - `SecretVault` encryption keys are generated in process memory (`crypto.randomBytes(32)`). This protects credentials from leaking into LLM prompt contexts and wire transcripts, but does not protect against local root attackers with host process memory access (e.g. `ptrace` or debugger attachments).
9. **AST Filter Nature (Structural Pattern Engine vs. Formal Sandbox)**:
   - The AST analyzer inspects syntax trees to unwind known execution wrappers and block dangerous primitives. It is a defense-in-depth syntactic filter, not an operating-system sandbox; full process containment requires the optional container sandbox.

---

## 🔬 Continuous Defense-in-Depth & Verification

To maintain resilience against novel attack techniques, MCP-Shield enforces:

1. **Automated Adversarial Fuzzing**: Property-based fuzzing (`fast-check`) and permutation testing (`npm run fuzz`) generating thousands of shell evasion mutations.
2. **Open Community Red-Team Program**: Ongoing submission of reproducible bypasses integrated into [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts).
3. **Transparent Benchmarking**: Latency overhead verified at `< 0.2 ms` median p50 in [BENCHMARKS.md](BENCHMARKS.md).
