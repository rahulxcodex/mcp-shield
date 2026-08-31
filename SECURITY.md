# Security Policy 🔒

The MCP-Shield team takes the security of developer environments and autonomous AI agent workflows very seriously. We appreciate the responsible disclosure of any vulnerabilities found in MCP-Shield.

---

## 🛡️ Supported Versions

We actively provide security patches for the following versions:

| Version Branch | Supported | Security Patch Cadence |
| :--- | :--- | :--- |
| **`1.x.x`** | :white_check_mark: Supported | Active / Immediate Hotfixes |
| **`< 1.0.0`** | :x: Unsupported | End-of-Life |

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability, bypass, or privilege escalation in MCP-Shield, **please do NOT report it in a public GitHub issue**.

### Preferred Reporting Channels

1. **GitHub Private Security Advisory**: Navigate to the repository's **Security** tab and select **"Report a vulnerability"**.
2. **Security Email**: Send an encrypted or direct email to **`security@example.com`**.

### Information to Include

To help us triage and resolve the issue quickly, please provide:

- **Vulnerability Category**: (e.g., AST command evasion, DLP secret extraction, DNS rebinding, COW path escape, rate-limiter bypass).
- **Step-by-Step Reproduction**: Detailed steps, command invocations, or a standalone test case matching [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts).
- **Impact Assessment**: What an attacker or compromised agent can achieve (e.g., arbitrary host command execution, credential theft).
- **Environment Details**: OS, Node.js version, and MCP client used (Claude Desktop, Cursor, Cline, Windsurf, etc.).
- **Proposed Mitigation**: If you have an idea for a patch, we welcome your feedback.

---

## ⏱️ Response Timelines & SLA

| Phase | Target Timeline | Action |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **< 48 hours** | We confirm receipt of your report and assign a maintainer. |
| **Triage & Reproducibility** | **< 5 business days** | We reproduce the issue and assess its CVSS severity score. |
| **Remediation & Patch** | **< 14 business days** | We develop and verify a fix in a private security fork. |
| **Coordinated Disclosure** | **Mutually Agreed** | We publish the release and credit the researcher. |

---

## 🔍 Severity Rating Matrix

We assess reports against the Common Vulnerability Scoring System (CVSS v3.1):

- **CRITICAL (CVSS 9.0 - 10.0)**: Direct host command execution without prompt, arbitrary file overwrites bypassing COW, or full credential dump.
- **HIGH (CVSS 7.0 - 8.9)**: Partial shell evasion bypasses, SSRF to cloud metadata endpoints, or sandbox escapes.
- **MEDIUM (CVSS 4.0 - 6.9)**: Rate-limiter bypasses, false-positive filter evasions, or denial-of-service via malformed JSON-RPC payloads.
- **LOW (CVSS 0.1 - 3.9)**: Minor logging inconsistencies or non-exploitable edge cases.

---

## 🎯 Threat Model & Architecture References

For detailed specifications on what is considered in-scope vs out-of-scope for the MCP-Shield security boundary:

- 🎯 [Threat Model](THREAT_MODEL.md)
- 📐 [Security Architecture](SECURITY_ARCHITECTURE.md)
- 📊 [Control Matrix](CONTROL_MATRIX.md)
- 🧪 [Red-Team Validation Program](REDTEAM.md)

---

## 🏆 Security Hall of Fame

We gratefully recognize and credit the security researchers and community contributors who help harden MCP-Shield:

- *Community contributors who responsibly disclose vulnerabilities will be permanently listed here and in our release notes.*
