# MCP-Shield

> [!WARNING]
> MCP-Shield is an experimental wire proxy designed to provide additional security controls for the Model Context Protocol (MCP) in local developer environments. It is currently in **early development** and has not undergone third-party security audits. Do not rely on it as your sole defense for highly sensitive production environments.

With the rapid adoption of AI IDEs and agents like **Claude Desktop**, **Cursor**, **Windsurf**, and **Cline**, granting AI unrestricted host privileges presents a security risk. MCP-Shield intercepts the JSON-RPC streams to apply filtering, rate limiting, and basic data loss prevention (DLP) before commands reach your OS.

## 🛡️ Key Features (In Development)

- **AST Command Filtering** - Uses `tree-sitter-bash` to parse and block some forms of arbitrary code execution and destructive commands. *(Note: Shell evasion is complex. While this blocks basic destructive patterns, it is not a foolproof sandbox.)*
- **Secret Redaction (DLP)** - Basic heuristics to detect and redact sensitive credentials before they reach the model.
- **Copy-on-Write (COW) Sandbox** - Safely intercepts AI file modifications to a staging directory for review.
- **Rate Limiting** - Helps prevent autonomous agents from getting stuck in infinite loops.
- **Egress Network Filtering** - Blocks basic LLM data exfiltration attempts by validating arguments against a blocklist.
- **Audit Logging** - Logs intercepted tool calls and policy decisions in JSONL format.

## 🚀 Getting Started

### Auto-Discover & Protect Your IDEs
MCP-Shield can automatically patch your existing MCP configurations to wrap your active servers in our proxy. Supported clients include **Claude Desktop**, **Cursor IDE**, **Cline**, and **Windsurf**.

```bash
# Install and run the auto-discovery protector
npx mcp-shield protect
```

### Manual Wrapping
You can secure any downstream MCP server manually by prefixing your start command:

```bash
npx mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/dev/workspace
```

## ⚙️ Configuration & Policy Engine

MCP-Shield is governed by a declarative YAML policy engine (`shield.config.default.yaml`). You can customize redaction thresholds, egress domains, and target-specific rule sets.

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
```

## 📈 Real-Time Web Dashboard

Gain visibility into your AI security posture. MCP-Shield includes an embedded Express/React web dashboard powered by WebSockets.
Monitor intercepted attacks, rate limits, and sanitized secrets in real-time at `http://localhost:3333`.

## ⚡ Performance & Benchmarks

MCP-Shield sits directly in the hot path of every AI agent tool call. We benchmark every release for latency and throughput:

- **End-to-End Proxy Overhead**: `< 0.2 ms` (p50 median)
- **AST Parsing Throughput**: `> 6,700 ops/sec` (< 150 µs per command)
- **Rate Limiting & Policy Evaluation**: `< 10 µs` (> 100,000 ops/sec)

See [BENCHMARKS.md](BENCHMARKS.md) for full reproducible latency percentiles and test environment specifications.

## 🎯 Adversarial Fuzzing & Red-Team Validation

We operate continuous adversarial fuzzing and an open community red-team challenge program to discover, patch, and test against bypass techniques:

- **Fuzzing Engine**: Automated permutation fuzzer testing quote mutations, wrapper chains (`sudo`, `env`, `nice`, `timeout`), traversal paths, redirections, and fork bombs.
- **Red-Team Program**: See [REDTEAM.md](REDTEAM.md) for rules of engagement, attack vectors, and how to submit reproducible bypass PoCs.

```bash
# Run the automated red-team test suite
npm run test:redteam

# Run the adversarial AST fuzzer (thousands of mutations)
npm run fuzz
```

## 📚 Learn More

- [Performance Benchmarks](BENCHMARKS.md) - Verified latency numbers across proxy components.
- [Red-Team Validation](REDTEAM.md) - Community security audit guidelines and bypass PoC submission.
- [Threat Model](THREAT_MODEL.md) - Understand the current security boundaries and limitations.
- [ADDITIONAL.md](ADDITIONAL.md) - A curated list of frameworks and resources.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information about contributing to this repository. We welcome feedback, adversarial testing, and pull requests!

## 🚀 Releasing

See [RELEASING.md](RELEASING.md) for how packages are published.

## 🔒 Security

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Community

- [GitHub Discussions](https://github.com/rahulxcodex/mcp-shield/discussions)

## 🌟 Support

If you find MCP-Shield useful as it matures, please consider starring the repository and contributing new features or improvements!
