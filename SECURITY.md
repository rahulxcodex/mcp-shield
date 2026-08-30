# Security Policy

## Supported Versions

Currently, MCP-Shield is in early development. Only the latest `main` branch is supported for security updates.

## Reporting a Vulnerability

We take security seriously, even at this early stage. If you discover a security vulnerability within MCP-Shield (including bypasses in the AST filter or DLP engine), please **do not open a public issue**.

Instead, please send an e-mail to `security@mcp-shield.local` or open a secure advisory on GitHub.

## Community Red-Team & Security Research

We operate an active [Red-Team Validation Program](REDTEAM.md). We welcome adversarial security audits, bypass attempts, and vulnerability disclosures.

- **Red-Team Guide**: See [REDTEAM.md](REDTEAM.md) for testing guidelines and scope.
- **Automated Validation Suite**: Run `npm run test:redteam` and `npm run fuzz` locally.

### Disclosure Process
1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours.
2. **Triage**: We will investigate and confirm the vulnerability against our automated test harness.
3. **Remediation**: We will work on a patch and notify you when it is ready.
4. **Release**: A fix will be published, and you will be permanently credited in the release notes and Hall of Fame.

## Security Hall of Fame

We would like to thank all security researchers and contributors who have helped harden MCP-Shield:

- *Open for community submissions via [REDTEAM.md](REDTEAM.md)*

