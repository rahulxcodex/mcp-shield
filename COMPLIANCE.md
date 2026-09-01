# MCP-Shield Enterprise Compliance & Regulatory Guide 🛡️

**Version:** 1.0  
**Target Certifications & Standards:** SOC 2 Type II, GDPR (EU 2016/679), HIPAA Security Rule (45 CFR § 164.312), NIST AI RMF 1.0, ISO/IEC 27001:2022  
**License Policy:** Permissive Commercial Open Source (MIT / Apache-2.0, Zero Copyleft Contamination)

---

## 1. Executive Summary

MCP-Shield serves as the enterprise security gateway and zero-trust proxy for Model Context Protocol (MCP) tool-augmented AI agents. In regulated enterprise environments (Financial Services, Healthcare, Defense, SaaS), deploying autonomous LLM agents introduces severe compliance risks:
* **Unauthorized Data Exfiltration (PII/PHI/Credentials)** via prompt injection or unvetted tool arguments.
* **Uncontrolled Agency & Destruction** through arbitrary command execution.
* **Non-Auditable AI Actions** failing regulatory evidence requirements.

MCP-Shield provides the deterministic security perimeter, cryptographic audit logging, and data loss prevention (DLP) required to satisfy Fortune 500 Chief Compliance Officers (CCO), Data Protection Officers (DPO), and Chief Information Security Officers (CISO).

---

## 2. SOC 2 Type II Trust Services Criteria (TSC) Mapping

MCP-Shield's security controls are directly aligned with the AICPA 2017 Trust Services Criteria for Security, Availability, Confidentiality, and Processing Integrity:

| SOC 2 Criterion | AICPA Description | MCP-Shield Control Implementation | Reference Control |
| :--- | :--- | :--- | :--- |
| **CC6.1** | Logical access security measures | Capability-based least privilege enforcement (`read-only`, `no-network`, `sandbox`) preventing privilege escalation. | [`CTL-06`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L16), [`CTL-09`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L19) |
| **CC6.6** | Boundary protection and traffic inspection | Multi-engine AST Firewall inspecting all subshell execution; DNS Rebinding and Egress Shield blocking RFC 1918 and metadata endpoints. | [`CTL-01`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L11), [`CTL-03`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L13) |
| **CC6.7** | Transmission data protection | In-transit stream inspection and zero-exposure tokenization between LLM clients and MCP servers. | [`CTL-02`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L12), [`CTL-10`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L20) |
| **CC6.8** | Prevention of unauthorized system changes | Copy-on-Write (COW) staging file system requiring explicit approval before applying mutating file edits. | [`CTL-04`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L14), [`CTL-05`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L15) |
| **CC7.1** | Threat detection & anomaly monitoring | Real-time sliding-window rate limiting, token anomaly tracking, and policy violation alerting. | [`CTL-07`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L17) |
| **CC7.2** | Security incident audit logging | Append-only, tamper-evident cryptographic log chaining (HMAC-SHA-256) recording every JSON-RPC invocation. | [`CTL-08`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L18) |
| **CC8.1** | Change management authorization | Declarative rule priority ladder (`QUARANTINE > BLOCK > PROMPT > SANDBOX > ALLOW`) version-controlled in YAML. | [`CTL-09`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L19) |

---

## 3. GDPR (EU General Data Protection Regulation) Alignment

MCP-Shield enables organizations to deploy AI agents in full compliance with EU Regulation 2016/679:

### Key GDPR Articles Addressed:

1. **Article 25 (Data Protection by Design and by Default):**
   * High-entropy DLP and regex sanitization strip Personally Identifiable Information (PII) before it is passed to third-party MCP servers or LLMs.
   * Bijective session tokenization replaces sensitive values with opaque surrogates (`<TOKEN_REDACTED_x>`), reversing substitutions only in approved, local response contexts.

2. **Article 28 (Processor Obligations & Data Minimization):**
   * Zero-retention proxy architecture: MCP-Shield processes JSON-RPC frames in volatile memory buffers without writing customer payloads to persistent third-party storage.

3. **Article 32 (Security of Processing):**
   * Multi-layered isolation prevents unauthorized code execution or container escapes from compromising underlying server infrastructure.

4. **Article 33 & 34 (Breach Notification & Audit Readiness):**
   * Immediate cryptographic logging of all policy violations and blocked exfiltration attempts provides instant forensics for incident response.

---

## 4. HIPAA (Health Insurance Portability and Accountability Act)

For healthcare providers and covered entities, MCP-Shield enforces strict **Technical Safeguards (45 CFR § 164.312)** for electronic Protected Health Information (ePHI):

### Technical Safeguard Matrix:

* **§ 164.312(a)(1) Access Control:**
  * Capability-based execution ensures AI agents cannot access unauthorized medical databases or file mounts.
* **§ 164.312(b) Audit Controls:**
  * Tamper-evident session logging captures who initiated an AI session, which tools were requested, what data transformations occurred, and whether any PHI redaction triggered.
* **§ 164.312(c)(1) Integrity Safeguards:**
  * Chained cryptographic hashing guarantees that session logs cannot be altered post-facto.
* **§ 164.312(e)(1) Transmission Security:**
  * Automatic DLP scanning prevents ePHI (HIPAA 18 Safe Harbor identifiers including SSNs, MRNs, medical device serial numbers, biometric records) from being leaked across MCP egress channels.

---

## 5. Software Supply Chain Security & SBOM Governance

Enterprise security demands complete transparency into third-party software components and zero tolerance for viral copyleft licensing risks.

### Supply Chain Controls:
* **CycloneDX v1.5 / 1.6 & SPDX Compliance:**
  * Machine-readable SBOMs (`mcp-shield.sbom.json`) generated in every CI/CD pipeline run.
* **Permissive Open Source Licensing:**
  * 100% of runtime dependencies are verified under permissive licenses (**MIT, Apache-2.0, BSD-3-Clause**).
  * Strict automated CI gate (`scripts/generate-sbom.js`) actively blocks any copyleft licenses (**GPL, AGPL, LGPL, SSPL**).
* **Zero Native Binary Blobs:**
  * Clean, portable TypeScript/Node.js runtime with minimal transitive dependencies to minimize CVE exposure.

---

## 6. Audit Logging & SIEM Integration Architecture

```
   ┌─────────────────────────────────────────────────────────┐
   │             MCP Client (Claude / Cursor / Copilot)      │
   └────────────────────────────┬────────────────────────────┘
                                │ JSON-RPC Request
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │                     MCP-Shield Gateway                  │
   │  ┌──────────────────┐  ┌──────────────────┐  ┌────────┐ │
   │  │  AST Firewall    │  │  DLP / Redactor  │  │ Sandbox│ │
   │  └────────┬─────────┘  └────────┬─────────┘  └────┬───┘ │
   └───────────┼─────────────────────┼─────────────────┼─────┘
               │                     │                 │
               ▼                     ▼                 ▼
   ┌─────────────────────────────────────────────────────────┐
   │         Tamper-Evident Chained Audit Logger             │
   │   • Record: { seq, timestamp, hash_prev, hash_curr }    │
   │   • HMAC-SHA-256 Signature Verification                 │
   │   • Zero-PII / Zero-Secret Payload Storage              │
   └────────────────────────────┬────────────────────────────┘
                                │
                                ▼ Structured JSONL
   ┌─────────────────────────────────────────────────────────┐
   │      Enterprise SIEM (Splunk / Datadog / AWS CW)        │
   └─────────────────────────────────────────────────────────┘
```

### Audit Log Schema Highlights:
* `sequenceId`: Monotonically increasing 64-bit integer.
* `sessionId`: UUIDv4 session identifier.
* `action`: Evaluated policy action (`ALLOW`, `BLOCK`, `REDACT`, `PROMPT`, `QUARANTINE`).
* `ruleId`: Identifier of the matched rule.
* `hashPrev`: SHA-256 digest of previous record.
* `hashCurr`: HMAC-SHA-256 digest over current payload.

---

## 7. Dual-Mode Deployment Governance

To satisfy both developer adoption and strict compliance auditing, MCP-Shield supports two operating modes:

1. **Observe (Audit-Only) Mode:**
   * Used during initial discovery and pilot onboarding.
   * Logs policy violations without terminating active MCP connections.
   * **Privacy Guarantee:** PII/PHI redaction remains enforced to prevent privacy violations during observation.

2. **Enforce (Fail-Closed) Mode:**
   * Mandated for SOC 2 Type II production environments.
   * Immediately blocks suspicious tool invocations, malformed syntax trees, or blacklisted network destinations.
   * Guarantees fail-closed isolation on internal parser exceptions.

---

## 8. Compliance Verification CLI

Verify compliance status and audit trails on-demand:

```bash
# Verify software bill of materials and license compliance
node scripts/generate-sbom.js

# Validate cryptographic integrity of session audit logs
mcp-shield audit-verify --log-dir .mcp-shield/logs

# Run complete compliance and security regression suite
npm test
```
