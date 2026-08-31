# MCP-Shield Red-Team & Security Research Program 🎯

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

| Category ID | Defensive Component | Target File | Primary Attack Vectors |
| :--- | :--- | :--- | :--- |
| **RT-CAT-01** | **AST Shell Firewall** | [`src/security/ast-analyzer.ts`](src/security/ast-analyzer.ts) | Shell evasions (`$IFS`, nested quotes, backslashes), invocation wrappers (`sudo`, `env`, `nice`, `stdbuf`, `timeout`, `pkexec`), compound statements, process substitutions, heredocs/herestrings, dangerous builtins, disk formatting (`dd`, `mkfs`), dynamic variable execution (`$VAR`), and DoS fork bombs. |
| **RT-CAT-02** | **Secret Sanitizer (DLP)** | [`src/security/sanitizer.ts`](src/security/sanitizer.ts)<br>[`src/security/vault.ts`](src/security/vault.ts) | High-entropy credential extraction, decoy honey-token access, token desynchronization, regex evasion, base64/hex encoding tricks, Unicode normalization tricks. |
| **RT-CAT-03** | **Policy Engine & Egress** | [`src/security/policy-engine.ts`](src/security/policy-engine.ts)<br>[`src/security/network-proxy.ts`](src/security/network-proxy.ts) | DNS rebinding, wildcard domain bypasses, IPv4-mapped IPv6, SSRF against link-local (`169.254.169.254`), path traversal in tool arguments (`/../`), schema spoofing. |
| **RT-CAT-04** | **Rate Limiter** | [`src/security/rate-limiter.ts`](src/security/rate-limiter.ts) | Tool naming case-sensitivity bypasses, burst loop evasion, timestamp overflow/skew, concurrency race conditions. |
| **RT-CAT-05** | **Sandbox & COW FS** | [`src/sandbox/cow-fs.ts`](src/sandbox/cow-fs.ts)<br>[`src/sandbox/container-sandbox.ts`](src/sandbox/container-sandbox.ts) | Staging path traversal, symlink resolution escapes, uncommitted diff tampering, container capability escalation. |

---

## 🧪 Testing Your Bypass Locally

Before submitting an advisory or pull request, please verify your findings using our automated testing harnesses:

### 1. Run the Red-Team Challenge Suite
```bash
npm run test:redteam
```

### 2. Run the Adversarial Bypass Corpus Regression Suite
```bash
npx jest tests/security-corpus/bypass-corpus.test.ts
```

### 3. Run Property-Based Fuzzing & Stress Tests
```bash
npx jest tests/security-corpus/property-based.test.ts
npm run fuzz
```

### 4. Run the Full Test Suite
```bash
npm test
```

---

## 📝 Submitting a Bypass / Vulnerability

### Option A: Community Bypass Challenge (Public Issue Template)
Submit your evasion payload through our [Bypass Challenge GitHub Issue Template](.github/ISSUE_TEMPLATE/security_bypass.yml). Submissions are automatically imported via `scripts/import-bypass.ts` and evaluated against the regression suite.

### Option B: Pull Request to `bypass-corpus.json` & `bypasses.test.ts`
1. Import your payload to `tests/security-corpus/bypass-corpus.json` using the helper:
   ```bash
   npx ts-node scripts/import-bypass.ts "ast_evasion_wrappers" "Description of bypass technique" "evasion_command_payload"
   ```
2. Add your dedicated regression test to [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts).

### Option C: Private Responsible Disclosure (Critical Zero-Days)
For critical zero-day vulnerabilities (direct host arbitrary code execution, complete sandbox breakouts, zero-day key extraction), please report privately via **`security@example.com`** or via GitHub Private Security Advisories per [SECURITY.md](SECURITY.md).

---

## 🏆 Hall of Fame & Acknowledgments

Contributors who submit novel bypasses or hardening improvements are permanently credited in:

- The [Security Hall of Fame & CVE Writeups in SECURITY.md](SECURITY.md)
- The [GitHub Release Notes](https://github.com/rahulxcodex/mcp-shield/releases)
- The [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts) test headers

Thank you for helping keep AI developer environments secure!

