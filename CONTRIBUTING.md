# Contributing to MCP-Shield 🤝

Thank you for your interest in contributing to **MCP-Shield**! We welcome contributions from developers, security researchers, and AI practitioners.

---

## 📜 Code of Conduct

All contributors and participants must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `security@example.com` or repository maintainers.

---

## 🛠️ Development Setup

### Prerequisites

- **Node.js**: `18.x`, `20.x`, `22.x`, or `24.x`
- **npm**: `9.x` or later
- **C/C++ Build Tools**: Required for compiling `tree-sitter` native bindings (e.g., `build-essential` on Linux, Xcode CLI tools on macOS, Visual Studio Build Tools / `windows-build-tools` on Windows)
- **Docker** *(Optional)*: Required for running container sandbox integration tests

### Clone & Install

```bash
# Clone the repository
git clone https://github.com/rahulxcodex/mcp-shield.git
cd mcp-shield

# Install dependencies (compiles native Tree-sitter bindings)
npm install

# Verify TypeScript compilation
npm run build
npm run typecheck
```

---

## 🧪 Running Tests & Quality Verification

MCP-Shield maintains an extensive test suite across unit, integration, red-team, and adversarial fuzzing harnesses:

```bash
# Run the full test suite (470+ tests across 14 test suites)
npm test

# Run the adversarial red-team bypass test suite
npm run test:redteam

# Run integration tests (stdio stream framing, proxy routing)
npm run test:integration

# Run the randomized AST fuzzer (thousands of command mutations)
npm run fuzz

# Run the performance benchmark suite
npm run bench
```

---

## 📁 Repository Structure

```
mcp-shield/
├── benchmarks/              # Performance latency & throughput benchmarks
├── bin/                     # CLI entrypoint executable
├── scripts/                 # Test runners and fuzzing harnesses
├── src/
│   ├── audit/               # Tamper-evident SHA-256/HMAC session logging
│   ├── cli/                 # CLI commands (install, scan, fix, protect, replay)
│   ├── core/                # JSON-RPC framing, proxy dispatching, session lifecycle
│   ├── dashboard/           # Real-time Express & WebSocket telemetry dashboard
│   ├── sandbox/             # Copy-on-Write (COW) FS & Docker container isolation
│   ├── security/            # AST analyzer, secret sanitizer, policy engine, egress proxy
│   └── tui/                 # Interactive terminal approval UI bridge
├── tests/
│   ├── fuzz/                # Permutation and property-based fuzzers
│   ├── integration/         # Stream framing & end-to-end proxy tests
│   ├── redteam/             # Adversarial bypass test corpus
│   └── unit/                # Unit tests for individual security modules
└── shield.config.default.yaml # Default declarative security policy configuration
```

---

## 📐 Architecture & Security Principles

When contributing code to MCP-Shield, adhere to these fundamental design rules:

1. **Fail-Closed by Default**: If an AST node cannot be parsed, a network request cannot be verified, or a timeout occurs, the proxy MUST block or quarantine the request.
2. **Zero-Overhead in Hot Paths**: Ensure hot-path operations (stream framing, secret scanning, policy evaluation) avoid costly allocations, synchronous file I/O, or unbounded loops.
3. **No Unsanitized Subprocesses**: Any external command execution MUST pass through AST analysis or container isolation.
4. **Deterministic Auditing**: All security events must be recorded through `SessionLogger` with sequential index tracking and cryptographic hashing.

---

## 🔄 Pull Request Workflow

1. **Fork the Repository**: Create a personal fork and create a descriptive branch:
   ```bash
   git checkout -b feature/new-security-check
   # or
   git checkout -b fix/ast-pipe-edgecase
   ```
2. **Implement Your Changes**: Write clean, modular TypeScript code with full test coverage.
3. **Validate Locally**: Ensure all tests, typechecks, and benchmarks pass:
   ```bash
   npm run typecheck
   npm test
   ```
4. **Submit a Pull Request**: Provide a clear summary of your changes, rationale, and reproduction steps for any bugs fixed.

---

## 🚨 Security Disclosures & Red-Team Submissions

- **Novel Bypasses & Red-Team Tests**: If you discover a novel evasion technique, please follow [REDTEAM.md](REDTEAM.md) to submit a reproducible test case.
- **Critical Zero-Days**: For critical host escapes or credential leakage zero-days, please disclose responsibly via [SECURITY.md](SECURITY.md) before opening public PRs.
