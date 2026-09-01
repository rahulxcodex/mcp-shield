# MCP Shield — Enterprise Pricing & Packaging Matrix 🛡️

MCP Shield provides zero-trust agentic security, AST shell command firewalls, and real-time DLP secret redaction for enterprise engineering teams deploying autonomous AI agents (Claude Desktop, Cursor, Windsurf, Cline, and custom agent runtimes).

---

## 📊 Plan Overview

| Feature Category | **Community (Open Source)** | **Team / Pro** | **Enterprise Grid** |
| :--- | :--- | :--- | :--- |
| **Target Audience** | Individual Developers & Open Source Researchers | Small Teams & Fast-Moving Startups (up to 50 seats) | Mid-Market & Fortune 500 Enterprises (50–10,000+ seats) |
| **Pricing Model** | **Free (MIT License)** | **$39 / developer / month** (billed annually) | **Custom Annual Contract** (Starting at $50,000 ACV) |
| **Deployment Model** | Local Endpoint CLI | Cloud SaaS Control Plane + Local Agent | Cloud SaaS, Dedicated Single-Tenant VPC, or On-Prem / Air-Gapped |
| **Core AST Firewall** | ✅ Full POSIX/Windows Tree-Sitter AST Analysis | ✅ Full POSIX/Windows Tree-Sitter AST Analysis | ✅ Full POSIX/Windows Tree-Sitter AST Analysis + Custom Rules |
| **DLP & Secret Redaction** | ✅ Regex & High-Entropy Detection (Local Masking) | ✅ Regex, High-Entropy & Custom Team Patterns | ✅ Bi-directional Vault-Backed Redaction + Zero-Knowledge Enclaves |
| **Evaluation Modes** | Fail-Closed Enforce Only | Fail-Closed Enforce + Observe / Audit Mode | Enforce, Observe/Audit, Shadow Pilot, & Per-Team Granular Rules |
| **Policy Distribution** | Local YAML Config Files (`shield.config.yaml`) | Web Dashboard & Team Policy Sync | Central Fleet Policy Push, Immutable GitOps & Tamper-Proof Signing |
| **Audit & Logging** | Local File Logs | Central Web Activity Log (30-day retention) | Real-time SIEM Export (Splunk, Datadog, Sentinel, Elastic) + 365-day retention |
| **Identity & Access** | None | Team SSO (Google Workspace, GitHub) | Enterprise SAML 2.0 / OIDC (Okta, Azure AD, Ping) + RBAC / SCIM |
| **Compliance & Reporting**| None | Basic Threat Statistics | SOC 2 Type II, ISO 27001, HIPAA & NIST AI RMF Automated Compliance Reports |
| **Support & SLAs** | Community Discord & GitHub Issues | Business Hours Email Support (<8 hr SLA) | **24/7/365 Dedicated P1 Support (<15 min SLA)** + Dedicated CSM |

---

## 🏢 Enterprise Grid Tier Deep-Dive

### 1. Deployment Flexibility
* **Multi-Tenant Secure Cloud:** Fast onboarding with isolated customer tenant keys and KMS encryption at rest.
* **Dedicated Single-Tenant VPC:** Hosted on AWS, GCP, or Azure in the customer's region of choice with dedicated control plane compute.
* **On-Premise / Air-Gapped Kubernetes:** Full Helm chart deployment into isolated enterprise Kubernetes clusters without external internet egress dependencies.

### 2. Centralized Fleet Management & Governance
* **Single-Pane-of-Glass Console:** Real-time visibility into all active agent connections, tool executions, and intercepted attacks across the entire developer workforce.
* **Policy Hierarchies & Inheritance:** Define organizational security baselines (e.g., global block on `rm -rf /`, credentials redaction) while allowing DevOps and engineering leads to define granular team-level allowances.
* **Immutable Audit Trail:** Cryptographically signed, append-only logs for tamper-evident compliance verification.

### 3. Custom AST Rule Engine & Proprietary Integrations
* Custom Tree-Sitter AST grammar extensions for internal CLI tools and propriety internal infrastructure commands.
* Integration with internal enterprise HashiCorp Vault, CyberArk, and AWS Secrets Manager for seamless runtime token injection.

---

## ⏱️ Service Level Agreements (SLAs) & Uptime

| Severity Level | Definition | First Response Target | Workaround / Resolution Target |
| :--- | :--- | :--- | :--- |
| **P1 — Critical** | Gateway control plane outage, proxy failure blocking critical engineering builds across team. | **< 15 minutes** (24/7/365) | < 2 hours |
| **P2 — Major** | Degraded performance, single-region policy distribution delay, or non-blocking policy parsing anomaly. | **< 1 hour** (24/7/365) | < 6 hours |
| **P3 — Moderate** | Feature issue with administrative dashboard, non-critical integration bug, or general support query. | **< 4 business hours** | < 24 business hours |
| **P4 — Low** | General inquiries, documentation clarifications, or feature requests. | **< 8 business hours** | Next sprint release |

### ⚡ Performance Latency Guarantee
* **AST Shell Parsing & Evaluation:** `< 500 microseconds (µs)` per command on standard endpoint hardware.
* **Gateway Proxy Overhead:** `< 1 millisecond (ms)` round-trip latency overhead on JSON-RPC MCP message exchanges.
* **Control Plane Availability:** `99.99%` monthly uptime for enterprise cloud control plane tiers.

---

## 💼 Enterprise Add-On Modules

| Add-On Module | Description | Annual Pricing |
| :--- | :--- | :--- |
| **Air-Gapped / Kubernetes Deployment Pack** | Packaged Helm charts, offline signature bundles, and air-gapped container images. | Included in Enterprise Custom ($15k/yr standalone) |
| **SIEM & Security Lake Streaming Connector** | Dedicated high-throughput Kafka / Syslog / S3 audit streaming connector for Splunk, Datadog & Sentinel. | Included in Enterprise Grid |
| **Custom DLP Pattern & ML Entity Redactor** | Custom trained Named Entity Recognition (NER) models for proprietary customer data schemas and PII formats. | $12,000 / year |
| **Dedicated Enterprise Security Architect** | 20 hours/month of dedicated advisory for custom AST policy authoring, threat modeling, and red-team audits. | $24,000 / year |

---

## 💬 Frequently Asked Questions (Procurement & Security)

### Q: Does MCP Shield send our proprietary source code to your cloud?
**No.** The MCP Shield Data Plane (AST engine, regex DLP, and command evaluation) executes **100% locally on the developer's machine or within your private VPC**. Only anonymized policy telemetry metadata and security event summaries are transmitted to the Central Control Plane.

### Q: What happens if the Central Control Plane is unreachable?
MCP Shield operates in **local caching mode**. The local proxy continues enforcing the last-known signed security policy offline, buffering non-critical audit telemetry until network connectivity is restored.

### Q: How do we initiate an Enterprise Pilot?
Enterprises can launch a 14-day zero-risk **"Observe-to-Enforce"** pilot. See our [POC Playbook](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/docs/POC_PLAYBOOK.md) for full onboarding details.
