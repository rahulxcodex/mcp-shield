# MCP-Shield — Operations Runbook

## 1. System Overview & Service Topology
The MCP-Shield production topology comprises:
1. **Public MCP Gateway / CLI**: Node.js 20+ runtime deployed either on client workstations (as an stdio proxy) or containerized behind reverse proxies.
2. **Private Enterprise Intelligence Microservice**: Deployed on Render (https://mcp-shield-enterprise-intel.onrender.com), protected by bearer tokens (X-MCP-Shield-Key).
3. **Private Licensing & Control Plane**: Deployed on Vercel (https://mcp-shield-licensing.vercel.app) with Supabase PostgreSQL backend (magfptvxgxscmlzphhlq.supabase.co) and Stripe Billing.

---

## 2. Startup & Health Checks
### Liveness vs Readiness
- **Liveness Endpoint (/health)**: Returns HTTP 200 {status:ok,timestamp:...} when the HTTP listener is operational and accepting TCP connections.
- **Readiness Endpoint (/api/health/ready)**: Verifies that database connections, signing keys, and required environment variables are valid. If dependencies are unavailable, returns HTTP 503 {status:degraded,ready:false}.
- Under zero circumstances will health or readiness endpoints disclose internal IP addresses, stack traces, database credentials, or secret keys.

---

## 3. Secret Management & Rotation Procedures
### 3.1 Policy Signing Key (LICENSE_PRIVATE_KEY)
- **Key Type**: Ed25519 PKCS8 PEM.
- **Rotation Frequency**: 90 days.
- **Procedure**:
  1. Generate new Ed25519 keypair via crypto.generateKeyPairSync('ed25519').
  2. Stage the new public key in gateway trusted key rings (support dual-verification window).
  3. Update LICENSE_PRIVATE_KEY in Vercel KMS environment variables.
  4. Redeploy mcp-shield-licensing.
  5. Issue a signed policy manifest with incremented policyVersion.
  6. Retire the old public key after the 24-hour TTL expiration window.

### 3.2 Enterprise Intel API Keys (ENTERPRISE_INTEL_SECRET, MCP_SHIELD_API_KEY)
- **Key Type**: High-entropy cryptographically random strings (mcpshld_live_...).
- **Rotation Frequency**: 60 days.
- **Procedure**:
  1. Register candidate key in IntelAuthManager.
  2. Deploy updated key to client gateway configurations.
  3. Validate successful telemetry and scoring invocations on Render logs.
  4. Mark old key as revoked via /api/v1/admin/keys/revoke.

---

## 4. Break-Glass Administration
In the event of active compromise, administrative break-glass enables emergency mitigation via /api/v1/admin/break-glass.
- **Mandatory Requirements**:
  - Request must be authenticated using the dedicated ADMIN_MASTER_KEY (never standard database service role keys).
  - Must include eason (minimum 5 characters) and confirmation: CONFIRM_BREAK_GLASS.
  - Durable audit record persistence is mandatory. If the audit database write fails, the break-glass action MUST abort and fail closed.
- **Supported Actions**:
  - key_revoke: Instantly revokes compromised API keys across the fleet.
  - customer_suspend: Suspends organization access and freezes outbound requests.
  - illing_correct: Manually synchronizes or corrects tenant subscription entitlements.
  - policy_rollback: Revokes bad policy bundles and forces fleet reversion to the known-safe baseline.

---

## 5. Capacity & Rate Limiting Guidelines
- Ingestion rate limit: Default 100 requests / second per project token; burst capacity 250 requests.
- Maximum payload ceiling: 1 MB per telemetry batch; 64 KB per enterprise intel scoring request.
- P99 latency SLO: < 15 ms pipeline decision time; < 250 µs P50 for deterministic AST / DLP checks.

---
*Maintained by MCP-Shield Platform Operations Team.*
