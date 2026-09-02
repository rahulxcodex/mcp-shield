# MCP-Shield Enterprise Compliance & Regulatory Guide 🛡️

**Version:** 2.0 (Enterprise GA Edition)  
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
| **CC6.1** | Logical access security measures | Capability-based least privilege enforcement (`read-only`, `no-network`, `sandbox`) & Dynamic Just-in-Time (JIT) Tool Elevation approvals. | [`CTL-06`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L16), [`CTL-09`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L19), [`CTL-13`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L23) |
| **CC6.6** | Boundary protection and traffic inspection | Multi-engine AST Firewall inspecting subshell execution; DNS Rebinding and Egress Shield blocking RFC 1918 and metadata endpoints. | [`CTL-01`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L11), [`CTL-03`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L13) |
| **CC6.7** | Transmission data protection | In-transit stream inspection, Format-Preserving Encryption (FPE), and zero-exposure tokenization between LLM clients and MCP servers. | [`CTL-02`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L12), [`CTL-10`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L20), [`CTL-11`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L21) |
| **CC6.8** | Prevention of unauthorized system changes | Copy-on-Write (COW) staging file system requiring explicit diff approval before applying mutating file edits. | [`CTL-04`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L14), [`CTL-05`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L15) |
| **CC7.1** | Threat detection & anomaly monitoring | Real-time sliding-window rate limiting, semantic token complexity throttling, and canary honeypot endpoint tripwires. | [`CTL-07`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L17), [`CTL-12`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L22) |
| **CC7.2** | Security incident audit logging | Append-only, tamper-evident cryptographic log chaining (HMAC-SHA-256) and watermarked audit trails recording every JSON-RPC invocation. | [`CTL-08`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L18), [`CTL-12`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L22) |
| **CC8.1** | Change management authorization | Declarative rule priority ladder (`QUARANTINE > BLOCK > PROMPT > SANDBOX > ALLOW`) version-controlled in YAML. | [`CTL-09`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L19) |

---

## 3. GDPR (EU General Data Protection Regulation) Alignment

MCP-Shield enables organizations to deploy AI agents in full compliance with EU Regulation 2016/679:

### Key GDPR Articles Addressed:

1. **Article 25 (Data Protection by Design and by Default):**
   * **Context-Aware DLP & Format-Preserving Encryption (FPE):** Replaces sensitive personal data (e.g. EU IBANs, National IDs, Emails) with schema-compliant cryptographic surrogates (`john.doe@acme.com` -> `<FPE_EMAIL_d81f2a>`). Downstream LLM tools process valid formats without exposing cleartext PII.
   * Bijective session tokenization restores real values only in approved, client-side response sinks.

2. **Article 28 (Processor Obligations & Data Minimization):**
   * Zero-retention proxy architecture: MCP-Shield processes JSON-RPC frames in volatile memory buffers without writing customer payloads to persistent third-party storage.

3. **Article 32 (Security of Processing):**
   * Multi-layered isolation (Container Sandboxing, COW FS) prevents unauthorized code execution or container escapes from compromising underlying server infrastructure.

4. **Article 33 & 34 (Breach Notification & Canary Tripwires):**
   * Synthetic **Honeypot MCP Endpoints** and **Cryptographic Watermarking Tripwires** trigger automated alerts the instant an attacker or rogue model attempts to exfiltrate decoy records.

---

## 4. HIPAA (Health Insurance Portability and Accountability Act)

For healthcare providers and covered entities, MCP-Shield enforces strict **Technical Safeguards (45 CFR § 164.312)** for electronic Protected Health Information (ePHI):

### Technical Safeguard Matrix:

* **§ 164.312(a)(1) Access Control & JIT Elevation:**
  * Capability-based execution ensures AI agents cannot access unauthorized medical databases or file mounts.
  * Mutating clinical operations require dynamic Just-In-Time (JIT) physician or admin sign-off.
* **§ 164.312(b) Audit Controls:**
  * Tamper-evident session logging captures who initiated an AI session, which tools were requested, what data transformations occurred, and whether any PHI redaction triggered.
* **§ 164.312(c)(1) Integrity Safeguards:**
  * Chained cryptographic hashing guarantees that session logs cannot be altered post-facto.
* **§ 164.312(e)(1) Transmission Security & Safe Harbor 18 Identifiers:**
  * Automatic DLP scanning prevents all 18 HIPAA Safe Harbor identifiers (SSNs, Medical Record Numbers, Health Plan Beneficiary numbers, Biometrics) from traversing MCP egress channels unmasked.

---

## 5. Advanced Compliance Features (External Auditor Recommendations)

### A. Context-Aware Format-Preserving Encryption (FPE)
To eliminate downstream tool validation crashes while protecting privacy, MCP-Shield supports Format-Preserving Encryption:
* **Medical Record Numbers:** `MRN-902341` ➔ `MRN-381904` (FPE tokenized)
* **Social Security Numbers:** `123-45-6789` ➔ `984-12-3901` (FPE tokenized)
* **Credit Cards:** `4111-2222-3333-4444` ➔ `4916-0000-0000-7777` (Luhn-valid surrogate)

### B. Honeypot MCP Servers & Exfiltration Watermarks
* **Canary Tool Definitions:** Transparently injects decoy MCP tools (`export_master_credentials`, `admin_emergency_override`) into agent tool lists. Any model call to a canary triggers an immediate SOC 2 security alert and session quarantine.
* **Cryptographic Watermarks:** Subtly embeds traceable entropy tripwire tokens into retrieved datasets to detect illicit model weight ingestion or data leakage.

### C. Dynamic Just-in-Time (JIT) Tool Elevation
* High-risk operations (e.g., database schema drop, batch email blast) generate an interactive elevation request in the audit stream requiring multi-party approval before execution.

---

## 6. Software Supply Chain Security & SBOM Governance

Enterprise security demands complete transparency into third-party software components and zero tolerance for viral copyleft licensing risks.

### Supply Chain Controls:
* **CycloneDX v1.6 & SPDX Compliance:**
  * Machine-readable SBOMs (`mcp-shield.sbom.json`) generated in every CI/CD pipeline run.
* **Permissive Open Source Licensing:**
  * 100% of runtime dependencies are verified under permissive licenses (**MIT, Apache-2.0, BSD-3-Clause**).
  * Strict automated CI gate ([`scripts/generate-sbom.js`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/scripts/generate-sbom.js)) actively blocks any copyleft licenses (**GPL, AGPL, LGPL, SSPL**).
* **Zero Native Binary Blobs:**
  * Clean, portable TypeScript/Node.js runtime with minimal transitive dependencies to minimize CVE exposure.

---

## 7. Audit Logging & SIEM Integration Architecture

```
   ┌─────────────────────────────────────────────────────────┐
   │             MCP Client (Claude / Cursor / Copilot)      │
   └────────────────────────────┬────────────────────────────┘
                                │ JSON-RPC Request
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │                     MCP-Shield Gateway                  │
   │  ┌──────────────────┐  ┌──────────────────┐  ┌────────┐ │
   │  │  AST Firewall    │  │  FPE & DLP       │  │ Sandbx │ │
   │  └────────┬─────────┘  └────────┬─────────┘  └────┬───┘ │
   │           │                     │                 │     │
   │           ▼                     ▼                 ▼     │
   │     ┌───────────────────────────────────────────────┐   │
   │     │    Canary & Watermark Tripwire Engine         │   │
   │     └───────────────────────┬───────────────────────┘   │
   └─────────────────────────────┼───────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────┐
   │         Tamper-Evident Chained Audit Logger             │
   │   • Record: { seq, timestamp, hash_prev, hash_curr }    │
   │   • HMAC-SHA-256 Signature Verification                 │
   │   • Zero-PII / Zero-Secret Payload Storage              │
   └────────────────────────────┬────────────────────────────┘
                                │ Structured JSONL
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │      Enterprise SIEM (Splunk / Datadog / AWS CW)        │
   └─────────────────────────────────────────────────────────┘
```

---

## 8. Dual-Mode Deployment Governance

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

## 9. Compliance Verification CLI

Verify compliance status and audit trails on-demand:

```bash
# Verify software bill of materials and license compliance
node scripts/generate-sbom.js

# Validate cryptographic integrity of session audit logs
mcp-shield audit-verify --log-dir .mcp-shield/logs

# Run complete compliance and security regression suite
npm test
```
