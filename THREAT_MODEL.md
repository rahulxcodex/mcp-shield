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

### ❌ Out-of-Scope (Known Limitations)

- **Pre-Compromised Host**: If an attacker already has root/kernel-level access to the host before MCP-Shield starts, security guarantees cannot hold.
- **Hardware & Side-Channel Attacks**: Hardware-level timing attacks or microarchitectural exploits (Spectre/Meltdown).
- **Social Engineering of the Operator**: If a human operator manually approves a destructive diff or dangerous command via prompt bridge, MCP-Shield respects the human decision.

---

## 🔬 Continuous Defense-in-Depth & Verification

To maintain resilience against novel attack techniques, MCP-Shield enforces:

1. **Automated Adversarial Fuzzing**: Property-based fuzzing (`fast-check`) and permutation testing (`npm run fuzz`) generating thousands of shell evasion mutations.
2. **Open Community Red-Team Program**: Ongoing submission of reproducible bypasses integrated into [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts).
3. **Transparent Benchmarking**: Latency overhead verified at `< 0.2 ms` median p50 in [BENCHMARKS.md](BENCHMARKS.md).
