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
6. **Windows PowerShell and cmd.exe Semantic Parsing**:
   - Multi-dialect semantic analysis is implemented across POSIX (`tree-sitter-bash`), PowerShell (`PowerShellASTAnalyzer` covering cmdlet aliases, parameter prefix matching, dynamic invocations `&`, base64 `-EncodedCommand` recursive inspection, and `$env:*` leakage), and cmd.exe (`CmdAnalyzer` covering carets, compound operators `&`/`&&`/`||`, delayed expansion `!VAR!`, and system tampering `vssadmin delete shadows`). All attack vectors are verified continuously in native Windows CI (`tests/security-corpus/windows/`).
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

---

## 🛡️ Expanded 18-Vector Threat Matrix (Roadmap Section 7)

| # | Threat Vector | Asset | Attacker Capability | Attack Path | Preventive Control | Detective Control | Response | Residual Risk | Test Coverage |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Malicious MCP Server** | Host system & secrets | Execute arbitrary binary / shell commands | Server advertises safe tools but invokes malicious OS code on call | Capability Broker (`CapabilityManifestRegistry`) default-deny + AST Guard | Schema drift monitor + AST syntax inspection | Immediate process termination + event log | Zero-day kernel exploit if host isolation disabled | `capability-execution-broker.test.ts`, `audit-enforce-modes.test.ts` |
| 2 | **Compromised MCP Server** | Downstream data & internal network | Hijacked upstream dependency | Attacker alters tool behavior post-initialization | Schema SHA-256 fingerprint attestation + ephemeral session isolation | Dynamic schema fingerprint drift detection | Quarantine tool identity + reject invocation | Compromise before initial fingerprint | `differential-parser.test.ts`, `round2-round3-remediation.test.ts` |
| 3 | **Malicious Tool Description** | LLM context & decision boundary | Inject jailbreaks into tool parameter descriptions | Craft hidden prompt injection instructions in `description` fields | ProtocolValidator schema stripping + Prompt Bridge Sanitizer | Regex and entropy analysis on tool descriptions | Strip unverified control metadata | Novel semantic jailbreak patterns | `protocol.test.ts`, `sanitizer.test.ts` |
| 4 | **Prompt Injection from Tool Outputs** | LLM conversational integrity | Inject adversarial prompts in tool return payloads | Tool returns malicious instructions disguised as data | OutputGuard Bijective DLP + output amplification bounds | Output volume check (>1MB) + secret marker scanner | Output truncation + error emission | Non-syntactic semantic persuasion | `capability-execution-broker.test.ts`, `output-guard.ts` |
| 5 | **Schema Poisoning** | Tool parameter trust boundary | Downstream server injects self-attested privilege flags | Attacker adds `_shieldCapabilities` to grant itself credentials | Untrusted schema attestation trap (CRIT-02 invariant) | Schema normalization stripping untrusted privilege keys | Forced `secretAccess: false` override | Malicious schema passing valid JSON-RPC | `round2-round3-remediation.test.ts` |
| 6 | **Tool Replacement** | Registered tool identity | Swap tool implementation dynamically | Server changes binary or function behind registered name | Immutable per-session tool identity + schema SHA-256 hash | Attestation fingerprint mismatch check | Block invocation (`SCHEMA_DRIFT_DETECTED`) | Unchanged parameter signature | `capability-manifest.ts`, `mutation-testing.test.ts` |
| 7 | **Dynamic Tool Registration** | Capability boundary | Register unauthorized high-privilege tools at runtime | Server emits dynamic `tools/list_changed` adding unvetted tools | Fail-closed unknown tool block (`UNKNOWN_TOOL_BLOCKED`) | Manifest registry lookup on every invocation | Inbound message drop + alert | Pre-authorized tool wildcard rules | `capability-execution-broker.test.ts` |
| 8 | **Server Binary Replacement** | Executable integrity | Tamper with local binary on disk | Attacker modifies MCP server executable between runs | Ephemeral launch from immutable container digests or pinned paths | File modification hash verification | Refusal to spawn unverified binary | Host root file modification | `container-sandbox.test.ts` |
| 9 | **Compromised Dependency** | Node.js process runtime | Malicious supply-chain package | Attacker introduces malicious transitive dependency | Lockfile signature checks (`npm audit signatures`) + CycloneDX SBOM | Automated Dependabot & Snyk scans | Package quarantine + pinned versions | Zero-day unannounced vulnerable version | `dependency-review.yml`, `reproducible-invariants.test.ts` |
| 10 | **Local Unprivileged Attacker** | IPC socket & file writes | Execute commands as local user | Intercept unauthenticated IPC or write to temp directories | Staging directory randomized permissions (`0o700`) + session IDs | Staging path verification before read | Drop compromised staging sessions | Shared unconfined temporary folders | `cow-fs.test.ts`, `cow-race.test.ts` |
| 11 | **Malicious Local Process** | Local dashboard & WebSocket | Connect to local telemetry endpoint | Local malware connects to localhost:3333 to hijack events | Constant-time token verification + HttpOnly cookies + Origin header check | Origin validation against bound localhost port | WebSocket closure (`4003 Forbidden`) | Memory scraping by local admin | `dashboard-cookie-auth.test.ts`, `server.ts` |
| 12 | **Network Attacker** | Ingress/Egress data | Eavesdrop or modify remote traffic | Man-in-the-middle attacks on external MCP connections | HTTPS CONNECT enforcement + TLS certificate validation | Socket destination inspection | Abort connection | Compromised system root CA | `network-proxy.ts`, `egress-deep-inspection.test.ts` |
| 13 | **DNS Attacker** | Egress destination IP | Poison DNS cache or perform DNS rebinding | Point allowed domain to `169.254.169.254` or loopback post-check | Multi-A/AAAA record verification + Socket-level IP connection pinning | IP classification before connection | Immediate connection drop | Host `/etc/hosts` poisoning | `ssrf-corpus.test.ts`, `ip-utils.test.ts` |
| 14 | **Dashboard Attacker** | Telemetry & policies | CSRF, token brute-force, or XSS | Attacker tricks user into opening malicious URL with dashboard token | Token stripped via 302 redirect + constant-time compare + HTML entity escaping | Rate limiter on auth endpoints | 401 Unauthorized | Stolen browser cookie store | `dashboard-cookie-auth.test.ts` |
| 15 | **Symlink / Junction Attacker** | Host filesystem | Create symlink or NTFS junction to escape workspace | Swap file with symlink between approval and commit (TOCTOU) | Canonical path resolution + `lstat` symlink rejection + commit mutex | Inode/file ID/size/hash verification pre-commit | `COW TOCTOU DETECTED` abort | File systems lacking inode primitives | `cow-fs.test.ts`, `cow-race.test.ts` |
| 16 | **Container Escape Attacker** | Host kernel & hardware | Exploit container runtime vulnerability | Attacker uses `CAP_SYS_ADMIN` or shared volumes to break out | `--cap-drop=ALL` + `--security-opt=no-new-privileges` + read-only root | Container exit code and crash telemetry | Sandbox termination | Linux kernel 0-day container breakout | `container-sandbox.test.ts` |
| 17 | **Credential Extraction Attacker** | API keys & passwords | Read secrets via prompt reflection or error messages | Prompt tool to echo environment variables or read `.env` | Ephemeral AES-256-GCM Secret Vault + Bijective tokenization | Pattern scanner + High-entropy Shannon detector | Secret replaced with `[[SHIELD_SECRET_*]]` | Extremely short low-entropy custom keys | `dlp-benchmark-validation.test.ts`, `vault.ts` |
| 18 | **Resource Exhaustion Attacker** | CPU, Memory, Disk | Infinite tool loops or gigabyte payload flooding | Agent generates infinite requests or gigabyte output strings | ProtocolValidator nesting depth ($\le 32$) + 1MB output cap + rate limiter | Sliding-window token-bucket quota tracking | Request drop + HTTP 429 / JSON-RPC error | Distributed distributed client floods | `rate-limiter-concurrency.test.ts`, `protocol.test.ts` |

