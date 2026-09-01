# MCP-Shield Enterprise Compliance & Vendor Assurance Pack 🛡️

**Document Classification:** Confidential / Enterprise Customer Facing  
**Target Audience:** Enterprise CISOs, Data Protection Officers (DPO), Chief Compliance Officers (CCO), Vendor Risk Management (VRM) Teams  
**Applicable Regulations & Standards:** SOC 2 Type II (AICPA), GDPR (EU 2016/679), HIPAA (45 CFR Part 164), NIST AI RMF 1.0, ISO/IEC 27001:2022  

---

## 1. Executive Summary & Zero-Trust Architecture

MCP-Shield provides the deterministic security gateway, continuous data loss prevention (DLP), and tamper-evident audit logging for Model Context Protocol (MCP) tool integrations. 

### Enterprise Risk Mitigation Summary
* **Zero Customer Data Retention:** By default, MCP-Shield processes JSON-RPC payloads entirely in volatile memory buffers with zero persistent raw payload storage.
* **Cryptographic Non-Repudiation:** Every MCP tool invocation, evaluation result, and policy violation is chained via HMAC-SHA-256 tamper-evident JSONL logs.
* **Privacy by Design (GDPR Art. 25 & HIPAA § 164.312):** Format-Preserving Encryption (FPE) and Shannon entropy DLP sanitize credentials, PII, and ePHI before transmission to downstream models.

---

## 2. Standardized Information Gathering (SIG) & CAIQ Pre-Filled Questionnaire

| Category | Question / Control Requirement | MCP-Shield Compliance Response | Evidence Reference |
| :--- | :--- | :--- | :--- |
| **Data Governance** | Does the solution store customer prompt or tool payload data? | **No.** In standard operation, the proxy operates under a zero-retention policy. Payload bodies are discarded from memory immediately after evaluation. | [`COMPLIANCE.md` §3](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/COMPLIANCE.md#L35) |
| **Access Control & RBAC** | How is access to MCP tools and administrative policies governed? | Capability-based least privilege enforcement (`read-only`, `no-network`, `sandbox`) paired with SAML 2.0 / OIDC SSO and RBAC roles (Admin, Security Officer, Developer, Auditor). | [`CONTROL_MATRIX.md` CTL-09](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L19) |
| **Audit & Logging** | How does the system prevent audit log tampering or suppression? | Every event is appended to a cryptographic hash chain where `hash_curr = HMAC_SHA256(hash_prev + sequence + timestamp + action)`. Sequence gaps or modified records immediately fail verification. | [`CONTROL_MATRIX.md` CTL-08](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L18) |
| **Encryption in Transit** | How is sensitive data protected during transmission between client and MCP server? | In-transit stream framing over TLS/mTLS, accompanied by Format-Preserving Encryption (FPE) and bijective tokenization for sensitive entities. | [`CONTROL_MATRIX.md` CTL-02](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L12) |
| **Vulnerability & Supply Chain** | What mechanisms ensure open-source dependencies are secure and compliant? | Automated CycloneDX v1.6 SBOM generation in every release; continuous CI scanning prohibiting viral copyleft licenses (GPL/AGPL) and CVEs. | [`scripts/generate-sbom.js`](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/scripts/generate-sbom.js) |
| **Privilege Escalation** | How does the gateway block malicious subshell command injection? | Multi-engine AST parser (`tree-sitter-bash`, `PowerShellASTAnalyzer`, `CmdAnalyzer`) unwinds wrappers, evaluates syntax trees, and blocks destructive execution. | [`CONTROL_MATRIX.md` CTL-01](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L11) |
| **Data Exfiltration** | How are SSRF and rogue outbound network connections prevented? | DNS rebinding protection, RFC 1918 private IP blocking, cloud metadata IP isolation (`169.254.169.254`), and domain blocklists/allowlists. | [`CONTROL_MATRIX.md` CTL-03](file:///c:/Users/Rahul/.gemini/antigravity/scratch/mcp-shield/CONTROL_MATRIX.md#L13) |

---

## 3. Enterprise Data Processing Addendum (DPA) Terms (GDPR Article 28)

1. **Scope and Roles:**
   * Customer acts as the **Data Controller**; MCP-Shield operates purely as a **Data Processor** (or security gateway subprocessor).
2. **Data Minimization:**
   * MCP-Shield enforces client-side DLP before any data is dispatched to AI providers or remote MCP servers.
3. **Subprocessors:**
   * The core proxy runs locally or within the customer's private cloud VPC (Docker / Kubernetes / Helm). No third-party subprocessors access raw customer telemetry without explicit opt-in.
4. **Data Subject Rights (GDPR Articles 15–22):**
   * Because MCP-Shield does not maintain persistent stores of personal data, right-to-be-forgotten requests are satisfied by default through zero-retention ephemeral buffers.

---

## 4. HIPAA Business Associate Agreement (BAA) Readiness (§ 164.312)

For Healthcare Covered Entities and Business Associates handling electronic Protected Health Information (ePHI):

### Technical Safeguard Implementation:
* **§ 164.312(a)(1) Access Control:** Restricts tool invocation to authenticated agent sessions; requires JIT human elevation for mutating queries.
* **§ 164.312(b) Audit Controls:** Real-time tamper-evident audit logs record all data access attempts and policy enforcement events without logging raw ePHI.
* **§ 164.312(c)(1) Data Integrity:** Hash-chained audit logs ensure that evidence of agent operations cannot be altered or deleted.
* **§ 164.312(e)(1) Transmission Security:** Automated PHI tokenization scrubs 18 Safe Harbor identifiers (MRN, SSN, Names, Dates, Biometrics) prior to external model transmission.

---

## 5. Software Supply Chain & Licensing Attestation

* **SBOM Standard:** CycloneDX 1.6 JSON (`mcp-shield.sbom.json`).
* **License Governance:** Strict Permissive Open Source (MIT, Apache-2.0, BSD-3-Clause).
* **Copyleft Exclusion:** 0% GPL, AGPL, LGPL, or SSPL code in core proxy or enterprise distributions.
* **IP Indemnification:** Commercial enterprise enterprise agreements include full IP infringement indemnification and enterprise SLA guarantees.
