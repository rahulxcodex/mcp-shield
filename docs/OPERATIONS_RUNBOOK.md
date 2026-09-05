# MCP-Shield — Operations Runbook

## 1. System Overview & Service Topology
The MCP-Shield production topology comprises:
1. **Public MCP Gateway / CLI**: Node.js 20+ runtime deployed either on client workstations (as an stdio proxy) or containerized behind reverse proxies.
2. **Private Enterprise Intelligence Microservice**: Deployed on Render (https://mcp-shield-enterprise-intel.onrender.com), protected by bearer tokens (X-MCP-Shield-Key).
3. **Private Licensing & Control Plane**: Deployed on Vercel (https://mcp-shield-licensing.vercel.app) with Supabase PostgreSQL backend (<project-ref>.supabase.co) and Stripe Billing.

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
  - Must include reason (minimum 5 characters) and confirmation: CONFIRM_BREAK_GLASS.
  - Durable audit record persistence is mandatory. If the audit database write fails, the break-glass action MUST abort and fail closed.
- **Supported Actions**:
  - key_revoke: Instantly revokes compromised API keys across the fleet.
  - customer_suspend: Suspends organization access and freezes outbound requests.
  - billing_correct: Manually synchronizes or corrects tenant subscription entitlements.
  - policy_rollback: Revokes bad policy bundles and forces fleet reversion to the known-safe baseline.

---

## 5. Capacity & Rate Limiting Guidelines
- Ingestion rate limit: Default 100 requests / second per project token; burst capacity 250 requests.
- Maximum payload ceiling: 1 MB per telemetry batch; 64 KB per enterprise intel scoring request.
- P99 latency SLO: < 15 ms pipeline decision time; < 250 µs P50 for deterministic AST / DLP checks.

---

## 6. Enterprise Intel Circuit Breaker, Hosting & Degraded-Mode Observability
### 6.1 Hosting Tier Architecture & Cold-Start Behavior
- **Evaluation**: The `mcp-shield-enterprise-intel` service (Render) and Hugging Face Space ML microservice operate on managed cloud environments. If running on free-tier instances, services spin down after 15 minutes of inactivity, introducing 30–60 second cold starts on initial requests.
- **Production Deployment Standard**: Production deployments must run on paid/persistent tiers (Render Starter/Standard or Cloud Run with `min_instances=1`) to eliminate cold-start latency spikes.
- **Circuit Breaker Thresholds**:
  - `failureThreshold`: 3 consecutive failures.
  - `resetTimeoutMs`: 30,000 ms (30 seconds).
  - `requestTimeout`: 1,200 ms via `AbortController`.
- **Degraded Mode & Observability**:
  - When the circuit breaker trips to `OPEN`, the gateway logs `CircuitBreaker: OPEN` and transitions decision routing to local fallback heuristics.
  - Decision responses explicitly report `source: 'LOCAL_FALLBACK'` in the `SecurityDecision` envelope.
  - Ops alerting monitors the ratio of `source === 'LOCAL_FALLBACK'` to total decisions via `/api/health/ready` and gateway telemetry.

### 6.2 Fail-Closed Invariant on High-Risk Vectors
- When the remote enterprise intelligence engine is unavailable or degraded:
  - Low-risk actions (e.g. read operations, low entropy) fall back gracefully to local deterministic heuristics (`ALLOW`).
  - High-risk operations (untrusted egress requested, credential canary hits > 0, or AST entropy >= 7.0) **STRICTLY FAIL CLOSED** with `verdict: 'BLOCK'`, `riskScore: 85`, and reason codes `['REMOTE_INTEL_UNAVAILABLE', 'HIGH_RISK_VECTOR_FAIL_CLOSED']`.
  - Under no circumstances does service degradation result in permissive security bypass.

---

## 7. Recurring Chaos Engineering & Disaster Recovery Drills
To ensure resilience against unexpected outages and verify fail-closed invariants end-to-end:
1. **Automated Chaos Suite**: Execute the chaos engineering suite:
   ```bash
   npm test -- tests/security/chaos-intel-fallback.test.ts
   ```
2. **Failure Scenarios Tested**:
   - **CHAOS-001**: Complete network blackhole / connection refused on port 59999 (verifies local fallback for low-risk actions).
   - **CHAOS-002**: Unreachable service during untrusted egress request (verifies fail-closed `BLOCK`).
   - **CHAOS-003**: Unreachable service during credential canary hit (verifies fail-closed `BLOCK`).
   - **CHAOS-004**: Upstream HTTP 503 Service Unavailable (verifies graceful circuit-breaker fallback).
   - **CHAOS-005**: Upstream recovery to HTTP 200 OK (verifies circuit-breaker recovery and authoritative remote verdict adoption).
3. **Monthly DR Drill**:
   - Run `npm run drill:dr` (`scripts/disaster-recovery-drill.ts`) to verify key revocation cascades, database transaction rollbacks, and tamper recovery.

---
*Maintained by MCP-Shield Platform Operations Team.*
