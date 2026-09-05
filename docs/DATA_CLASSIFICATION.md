# MCP-Shield — Data Classification & Retention Policy

## 1. Data Classification Tiers

| Tier | Classification | Description | Examples | Storage & Encryption Requirements | Retention Period |
|---|---|---|---|---|---|
| **Tier 1** | Crown Jewel / Secret | Proprietary algorithms, cryptographic private keys, raw weaponized attack corpus. | Ed25519 private keys, scoring weight exponents, private corpus rules. | Isolated private repositories, KMS hardware encryption, strictly zero client transmission. | Indefinite (Managed lifecycle) |
| **Tier 2** | Confidential Tenant Data | Organization credentials, API keys, customer membership lists, billing details. | Project API key hashes, Stripe customer IDs, organization member emails. | Encrypted at rest (AES-256 / pgcrypto), RLS enforced, HTTPS TLS 1.3 in transit. | Duration of active subscription + 30 days |
| **Tier 3** | Operational Telemetry | Sanitized event receipts, tool usage counts, latency metrics, redacted audit trails. | Execution decision records, blocked threat counters, tool execution timings. | Redacted prior to ingestion; no plaintext tokens or passwords permitted. | 90 days rolling window |
| **Tier 4** | Public / Open Source | Core gateway code, public documentation, open benchmark suites. | AST firewall rules, CLI source code, public npm package binaries. | Public GitHub repository, signed npm package registries. | Permanent |

---

## 2. Redaction & Privacy Mandate
Under Tier 3 (Operational Telemetry), all incoming data must pass through the IncrementalSecretScanner and privacy-telemetry pipeline before persistence.
- Any API keys (mcpshld_live_, sk_live_, ghp_, glpat-) are replaced with [REDACTED_API_KEY].
- Bearer tokens are replaced with Bearer [REDACTED_TOKEN].
- RSA/EC private keys are scrubbed and replaced with [REDACTED_PRIVATE_KEY].
- Telemetry payloads violating size (>1 MB) or containing unredacted raw binary files are dropped at the gateway boundary.

---

## 3. Data Deletion Procedures
When an organization requests account deletion:
1. DELETE FROM organizations WHERE id =  cascades deletions to projects, pi_keys, gent_instances, and organization_members.
2. Telemetry logs and security events are purged after the 30-day compliance retention window.
3. Stripe customer subscription is canceled immediately.

---
*Maintained by MCP-Shield Compliance & Data Protection Office.*
