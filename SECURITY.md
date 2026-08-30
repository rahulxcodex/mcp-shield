# Security Policy

## Supported Versions

Currently, only the `main` branch and the latest published stable release (`1.x`) are actively supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of MCP-Shield very seriously. If you discover a vulnerability, please do NOT open a public issue.

Instead, please email your findings to `security@example.com` or use the GitHub Security Advisory "Report a Vulnerability" feature on this repository.

### What to include in your report

- A descriptive summary of the vulnerability.
- Steps to reproduce the issue (including any PoC scripts or configurations).
- The potential impact (e.g., bypass of AST rules, sandbox escape).
- Your proposed remediation, if you have one.

### Response Timeline

- We will acknowledge receipt of your vulnerability report within **48 hours**.
- We will provide a status update or a remediation plan within **7 days**.
- Once a fix is verified, we will coordinate a public disclosure (CVE assignment if applicable) and credit you for the discovery.

## Threat Model

For details on what is explicitly considered in-scope vs out-of-scope for the MCP-Shield security boundary, please read our [Threat Model](./THREAT_MODEL.md).
