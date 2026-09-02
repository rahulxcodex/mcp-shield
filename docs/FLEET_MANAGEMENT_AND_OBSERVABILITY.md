# Enterprise Fleet Management & Observability Guide (Phases 2 & 3 GA)

This document details the multi-tenant architecture, fleet management, SSO/OIDC integration, Honeypot Canary defenses, and observability operations for **MCP Shield**.

---

## 1. Multi-Tenant Fleet Architecture

In large enterprises, multiple engineering organizations and AI agent clusters share proxy infrastructure. MCP Shield enforces strict logical and cryptographic tenant isolation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Enterprise Fleet Gateway                           │
│                                                                             │
│  [ Agent Org A ] ──▶ (Header: X-MCP-Shield-Tenant-ID: tenant-a) ──┐        │
│  [ Agent Org B ] ──▶ (Header: X-MCP-Shield-Tenant-ID: tenant-b) ──┼──▶ [MCP│
│  [ Agent Org C ] ──▶ (Header: X-MCP-Shield-Tenant-ID: tenant-c) ──┘   Shield│
│                                                                        Mesh]│
│                                                                             │
│           ┌─────────────────── Tenant Policies ──────────────────┐          │
│           │ Tenant A: Policy 'Finance-Restricted' (Strict Block)  │          │
│           │ Tenant B: Policy 'Dev-Sandboxed' (CoW Enabled)        │          │
│           │ Tenant C: Policy 'Observe-Only' (Audit Shadow)        │          │
│           └──────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Multi-Tenancy Configuration in Helm
Set tenant parameters in `values.yaml`:

```yaml
multiTenancy:
  enabled: true
  tenantHeader: "X-MCP-Shield-Tenant-ID"
  defaultTenant: "default-enterprise"
  isolationPolicy: "strict-namespace"
```

---

## 2. Enterprise Single Sign-On (SSO) & OIDC Integration

MCP Shield integrates with enterprise identity providers (Okta, Azure AD, Keycloak, Ping Identity) via OpenID Connect (OIDC) for dashboard access and administrative control:

```yaml
sso:
  enabled: true
  provider: "oidc"
  issuerUrl: "https://auth.corp.enterprise.com/oauth2/v1"
  clientId: "mcp-shield-gateway"
  clientSecretSecretName: "mcp-shield-sso-secret"
  roleClaim: "groups"
  adminGroup: "secops-admins"
  auditorGroup: "compliance-auditors"
```

### Role-Based Access Control (RBAC)
- **`secops-admins`**: Full read/write access to update proxy rules, toggle shadow/enforce modes, and release quarantined agent sessions.
- **`compliance-auditors`**: Read-only access to tamper-evident audit logs, SHA-256 integrity trees, and violation analytics.
- **`developers`**: Access to view their tenant's real-time latency, token consumption, and blocked request debug logs.

---

## 3. Canary Honeypot Endpoints (Auditor Recommendation #4)

MCP Shield deploys active canary decoy tools (`aws_escalate_admin_iam`, `database_dump_all_credentials`, `host_root_debug_shell`) into the agent's discoverable tool registry.

```
AI Agent Prompt Hijack / Jailbreak Attempt
                 │
                 ▼
       Calls Decoy Canary Tool
                 │
                 ▼
 🚨 [CANARY HONEYPOT TRAP TRIGGERED]
  ├── 1. Gateway halts execution immediately (Upstream tools unreachable)
  ├── 2. Emits critical metric: mcp_shield_honeypot_triggers_total
  ├── 3. Pushes instant webhook alert to SIEM / PagerDuty / Slack SecOps
  └── 4. Dynamically quarantines agent session & issues forensic snapshot
```

### Enabling Honeypots in Helm

```yaml
honeypot:
  enabled: true
  canaryService: "mcp-shield-honeypot"
  trapAction: "quarantine-session-and-alert"
  alertWebhook: "https://security-alerts.enterprise.internal/tripwire"
```

---

## 4. Semantic Rate Limiting (Auditor Recommendation #3)

Standard requests-per-second (RPS) rate limiters are insufficient for AI agents, where a single call can trigger a massive token context consumption or combinatorial tool execution loop.

MCP Shield implements **Semantic Rate Limiting**:
- **Token Budgeting**: Allocates per-tenant rolling token limits per minute (e.g., 500,000 tokens/min).
- **Tool Complexity Scoring**: Assigns weights to sensitive tools (e.g., Bash execution = 50 points, read-only calculator = 1 point). If a burst exceeds the complexity budget, the gateway throttles the agent before upstream saturation occurs.

```yaml
semanticRateLimiting:
  enabled: true
  strategy: "token-complexity"
  tokenBudgetPerMinute: 500000
  maxComplexityScorePerCall: 100
  burstMultiplier: 1.5
```

---

## 5. Grafana Dashboards & Prometheus Alerts

### Importing the Dashboard
1. Open Grafana (`http://grafana.internal:3000`).
2. Navigate to **Dashboards > Import**.
3. Upload `deploy/observability/grafana-dashboard.json`.
4. Select your enterprise Prometheus data source.

### Key Monitored Panels
- **p99 Proxy Latency Overhead**: Evaluates compliance with the <5ms SLA.
- **Canary / Honeypot Traps**: Real-time ticker of prompt injection traps.
- **Security Violations Breakdown**: Categorized by rule ID, risk level, and tenant.
- **Semantic Rate Limit Throttling**: Live tracking of token consumption.

---

## 6. Verifying Signed Container Images (Cosign & SLSA)

All production container images published to `ghcr.io/rahulxcodex/mcp-shield` are keyless-signed with Sigstore/Cosign and include SLSA provenance attestations.

To verify image signatures prior to Kubernetes cluster deployment:

```bash
# Verify image signature with Cosign
cosign verify ghcr.io/rahulxcodex/mcp-shield:1.0.0 \
  --certificate-identity-regexp "https://github.com/rahulxcodex/mcp-shield/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

To enforce admission verification in Kubernetes, deploy an admission controller policy (Kyverno or OPA Gatekeeper) matching the Cosign certificate issuer.
