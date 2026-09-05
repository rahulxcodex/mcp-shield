# MCP-Shield — Security Incident Response Plan

## 1. Incident Classification
| Severity Level | Definition | Response SLA | Escalation Target |
|---|---|---|---|
| **SEV-1 (Critical)** | Active bypass of execution broker, private signing key exposure, cross-tenant data leak, or compromised enterprise intel service. | 15 minutes | Lead Architect, Principal Security Engineer, Incident Commander |
| **SEV-2 (High)** | Single-tenant API key compromise, AST evasion discovery without weaponization, or billing synchronization failure. | 1 hour | Security Engineering Team |
| **SEV-3 (Medium)** | Telemetry ingestion rate limit spikes, non-exploitable memory leak, or documentation discrepancy. | 8 hours | On-call Platform Engineer |

---

## 2. Incident Playbooks

### 2.1 Leaked Signing Key (LICENSE_PRIVATE_KEY)
1. **Immediate Revocation**: Mark the current key identifier as revoked in mcp-shield-licensing.
2. **Key Generation**: Provision a fresh Ed25519 keypair and deploy private key to KMS.
3. **Policy Bump**: Publish policy manifest with bumped epoch version. Clients encountering revoked signers reject policy downloads and fallback to secure local immutable defaults.
4. **Audit Audit**: Review /api/v1/admin/audit-logs for unauthorized manifest generation.

### 2.2 Stolen Project API Key
1. **Revoke Key**: Invoke /api/v1/admin/break-glass with ction: key_revoke, targeting the leaked API key ID.
2. **Issue Replacement**: Prompt tenant administrator to generate a fresh key in the console.
3. **Inspect Telemetry**: Run query on security_events for anomalous client IPs or unusual tool invocations during the suspected window.

### 2.3 Malicious MCP Server Discovery
1. **Schema Pinning**: Extract MCP server signature (server_hash) from agent telemetry.
2. **Global Blacklist**: Inject server signature into SEC-POL-GLOBAL blacklist.
3. **Fleet Broadcast**: Push emergency policy sync to connected agents; IngressGuard immediately terminates connections to the malicious server.

### 2.4 Prompt-Injection / Exfiltration Campaign
1. **Quarantine Activation**: IngressGuard flags repetitive suspicious sequences and promotes agent session to QUARANTINED.
2. **Egress Lock**: Execution broker terminates all outbound sockets for the tainted process tree.
3. **Forensic Dump**: Export cryptographic audit batch with Merkle root proof for offline threat investigation.

---

## 3. Post-Incident Review & Evidence Preservation
- Cryptographic audit batches (udit_batches) and signed event receipts provide tamper-evident proofs for SOC 2 and ISO 27001 compliance.
- No incident may be closed without root cause identification, unit regression test addition, and verified gate execution.

---
*Maintained by MCP-Shield Incident Response & Security Team.*
