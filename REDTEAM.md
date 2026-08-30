# MCP-Shield Red-Team & Security Research Program

> **Empowering the security community to audit, stress-test, and harden the AI Agent Gateway.**

Security tools live or die by their resilience under adversarial pressure. Rather than relying on security-by-obscurity, MCP-Shield operates an open **Community Red-Team Validation Program**. We actively encourage security researchers, penetration testers, and AI security practitioners to discover and report bypass techniques, evasions, and architectural vulnerabilities.

---

## 🎯 Program Objectives

1. **Continuous Surface Hardening**: Discover edge cases in AST parsing, argument deserialization, and path normalization before malicious actors do.
2. **Deterministic Regression Protection**: Every confirmed bypass PoC is converted into an automated unit/regression test in [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts).
3. **Transparent Defense**: Document real-world adversarial attack vectors and their corresponding defensive mitigations.

---

## 🎯 Target Scope & Attack Surfaces

Researchers are encouraged to probe the following primary defensive components:

| Component | Target File | Primary Attack Vectors |
| :--- | :--- | :--- |
| **AST Firewall** | [`src/security/ast-analyzer.ts`](src/security/ast-analyzer.ts) | Shell evasions (`$IFS`, quotes, backslashes), invocation wrappers (`sudo`, `env`, `nice`, `stdbuf`), compound statements, process substitutions, heredocs/herestrings, dangerous builtins, disk formatting, and DoS bombs. |
| **Secret Sanitizer (DLP)** | [`src/security/sanitizer.ts`](src/security/sanitizer.ts) | High-entropy credential extraction, decoy honey-token access, token desynchronization, regex evasion, Unicode normalization tricks. |
| **Policy Engine & Egress** | [`src/security/policy-engine.ts`](src/security/policy-engine.ts) | Wildcard domain bypasses, IPv4-mapped IPv6, punycode, path traversal in tool arguments (`/../`), schema spoofing. |
| **Rate Limiter** | [`src/security/rate-limiter.ts`](src/security/rate-limiter.ts) | Tool naming case-sensitivity bypasses, burst loop evasion, timestamp overflow/skew. |
| **COW Sandbox** | [`src/sandbox/cow-fs.ts`](src/sandbox/cow-fs.ts) | Staging path traversal, symlink resolution escapes, uncommitted diff tampering. |

---

## 🧪 Testing Your Bypass Locally

Before submitting an advisory or pull request, please verify your findings using our automated testing harnesses:

### 1. Run the Red-Team Challenge Suite
```bash
npm run test:redteam
```

### 2. Run the Adversarial AST Fuzzer (Thousands of Mutations)
```bash
npm run fuzz
```

### 3. Run the Full Test Suite
```bash
npm test
```

---

## 📝 Submitting a Bypass / Vulnerability

### Step 1: Prepare a Minimal Reproducible PoC
Create a standalone snippet or test case following the format in `tests/redteam/bypasses.test.ts`:

```typescript
it('RT-XXXX: [Short Title of Bypass Technique]', () => {
  const payload = '...';
  const result = analyzer.analyzeCommand(payload);
  // Demonstrate that the evasion bypasses current defenses or crashes the gateway
  expect(result.isSafe).toBe(true); // Demonstrates bypass
});
```

### Step 2: Responsible Disclosure
- For non-critical bug reports or test contributions, open a PR adding the test to `tests/redteam/`.
- For critical bypasses (e.g., remote code execution on host, complete sandbox escape, zero-day DLP extraction), report privately to **`security@mcp-shield.local`** or open a private GitHub Security Advisory in accordance with [SECURITY.md](SECURITY.md).

---

## 🏆 Hall of Fame & Acknowledgments

Contributors who submit novel bypasses or hardening improvements will be permanently credited in:
- The [GitHub Release Notes](https://github.com/rahulxcodex/mcp-shield/releases)
- The Security Hall of Fame section in `SECURITY.md`
- The `tests/redteam/bypasses.test.ts` test headers

Thank you for helping keep AI developer environments secure!
