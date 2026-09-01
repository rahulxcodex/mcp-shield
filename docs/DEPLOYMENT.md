# Enterprise Deployment & SRE Operations Guide

This guide details how to deploy, operate, scale, and monitor **MCP Shield** across production enterprise Kubernetes, Docker, and hybrid-cloud environments.

---

## 1. Deployment Topologies

MCP Shield supports two primary enterprise deployment topologies:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Topology A: Centralized Ingress/Egress Gateway Mode (Recommended for SaaS) │
│                                                                             │
│   [ AI Agent Pod ] ──(MCP JSON-RPC)──▶ [ MCP Shield Gateway (HA) ]         │
│                                                   │                         │
│                                          (Evaluated Traffic)                │
│                                                   ▼                         │
│                                         [ Upstream MCP Tool ]               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Topology B: Kubernetes Sidecar Injection Mode (Zero-Trust Local Proxy)      │
│                                                                             │
│   ┌────────────────────────── Kube Pod ───────────────────────────────┐     │
│   │ [ AI Agent Container ] ──(localhost:3333)──▶ [ MCP Shield Sidecar ] │    │
│   └───────────────────────────────────────────────────┬───────────────┘     │
│                                                       ▼                     │
│                                            [ Upstream MCP Server ]          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Quickstart: 1-Command Demo Stack

To spin up a local live demo with a mock vulnerable MCP upstream server:

```bash
# 1. Start the stack
docker compose -f docker-compose.demo.yml up -d

# 2. Run the automated live exploit demo (Linux/macOS)
./scripts/demo-exploit.sh

# Or on Windows PowerShell:
.\scripts\demo-exploit.ps1
```

---

## 3. Kubernetes Deployment via Helm

### Prerequisites
- Kubernetes `v1.26+`
- Helm `v3.10+`

### Installation

```bash
# Install or upgrade MCP Shield in production namespace
helm upgrade --install mcp-shield ./deploy/helm/mcp-shield \
  --namespace mcp-shield-system \
  --create-namespace \
  --values ./deploy/helm/mcp-shield/values.yaml
```

### GitOps with ArgoCD
To deploy via ArgoCD, define an `Application` manifest:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: mcp-shield
  namespace: argocd
spec:
  project: default
  source:
    repoURL: 'https://github.com/rahulxcodex/mcp-shield.git'
    targetRevision: main
    path: deploy/helm/mcp-shield
    helm:
      valueFiles:
        - values.yaml
  destination:
    server: 'https://kubernetes.default.svc'
    namespace: mcp-shield-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

---

## 4. Operational Lifecycle: Shadow vs. Enforce Mode

To adopt MCP Shield without risking service disruption to mission-critical AI agents:

### Phase 1: Shadow / Observe Mode (`observe`)
In `observe` mode, MCP Shield evaluates all JSON-RPC payloads, computes risk levels, logs security alerts, and emits Prometheus metrics, but **passes the traffic through without blocking**.

```bash
helm upgrade mcp-shield ./deploy/helm/mcp-shield \
  --namespace mcp-shield-system \
  --set enforcementMode=observe
```

### Phase 2: Active Fail-Closed Enforcement (`enforce`)
Once baseline traffic is audited and security rules are refined, switch to `enforce` mode:

```bash
helm upgrade mcp-shield ./deploy/helm/mcp-shield \
  --namespace mcp-shield-system \
  --set enforcementMode=enforce
```

---

## 5. Enterprise Observability & Metrics

### Prometheus Scraping
MCP Shield exposes standard Prometheus metrics on port `3333` at `/metrics`.

Key metric endpoints:
- `mcp_shield_requests_total{action="allow|block|redact", rule_id="..."}`: Total evaluated MCP tool requests.
- `mcp_shield_request_duration_seconds`: Proxy latency histogram (p50, p95, p99).
- `mcp_shield_security_violations_total{risk="CRITICAL|HIGH|MEDIUM"}`: Blocked attack attempts.

If using Prometheus Operator, enable the ServiceMonitor in `values.yaml`:

```yaml
serviceMonitor:
  enabled: true
  interval: 15s
```

### Health & Readiness Probes
- Liveness: `GET http://localhost:3333/healthz` (returns HTTP 200)
- Readiness: `GET http://localhost:3333/readyz` (returns HTTP 200 when rules and sandboxes are loaded)

---

## 6. Container Hardening & Security Profile

MCP Shield is engineered to pass strict enterprise admission controllers (OPA Gatekeeper, Kyverno):
- **Rootless Execution**: Runs as non-root user `node` (UID `1000`).
- **Read-Only Root Filesystem**: `readOnlyRootFilesystem: true` with ephemeral `tmpfs` mounts for temporary staging.
- **Capabilities Dropped**: `ALL` Linux capabilities dropped.
- **No Privilege Escalation**: `allowPrivilegeEscalation: false`.
- **Seccomp Profile**: `RuntimeDefault`.
- **Minimal Image**: Multi-stage Alpine/Distroless build free of unnecessary tooling.
