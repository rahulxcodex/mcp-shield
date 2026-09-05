# MCP-Shield — Formal Production Acceptance Matrix

## Specification Overview
This matrix establishes the definitive acceptance criteria for the three repositories comprising the MCP-Shield ecosystem:
1. mcp-shield (Open Source Zero-Trust Execution Broker, Proxy, CLI & Cloud Dashboard)
2. mcp-shield-enterprise-intel (Private Enterprise Threat Intelligence Microservice)
3. mcp-shield-licensing (Private Licensing, Telemetry Ingestion & Control Plane)

Every control is verified through executable commands. A gate is FAILING if tests are missing, skipped, mock-only, or hardcoded.

---

## 1. Production Acceptance Matrix

| Control ID | Severity | Requirement | Exact Implementation Location | Exact Executable Test Command | Test File & Case Name | Expected Failure Behavior | Evidence Artifact | Environment Assumptions | Status |
|---|---|---|---|---|---|---|---|---|---|
| **SEC-GATE-001** | CRITICAL | Single source of truth contracts & documentation established | docs/PRODUCTION_READINESS.md, docs/PRODUCTION_ACCEPTANCE_MATRIX.md | 
px ts-node scripts/check-production-readiness.ts | check-production-readiness.ts:SEC-GATE-001 | Non-zero exit code if required docs are absent or missing required sections | eports/production-certification.json | Clean git checkout | EXECUTED_PASS |
| **SEC-GATE-002** | CRITICAL | Zero production credential fallbacks; fail-closed startup | src/config/environment.ts, licensing/src/lib/config.ts | 
pm test -- tests/config/environment-validation.test.ts | environment-validation.test.ts:ENV-001..003 | Throws immediately on missing or dummy secrets in production | eports/evidence/env-validation.json | Node 20+, NODE_ENV=production | EXECUTED_PASS |
| **SEC-GATE-003** | CRITICAL | JSON-RPC protocol bounding, nesting depth, cancellation & ID uniqueness | src/proxy/mcp-gateway.ts, src/security/protocol/json-rpc-guard.ts | 
pm test -- tests/security-corpus/protocol-property-based.test.ts | protocol-property-based.test.ts:PROP-001..004 | 400 Bad Request / JSON-RPC parse error (-32700 / -32600) | eports/evidence/protocol-bounds.json | Deterministic unit runner | EXECUTED_PASS |
| **SEC-GATE-004** | CRITICAL | AST parser differential evasion resistance & Unicode normalizer | src/security/ast-analyzer.ts, src/security/interpreter-analyzer.ts | 
pm test -- tests/redteam/ast-evasion-redteam.test.ts | st-evasion-redteam.test.ts:AST-001..010 | Hard BLOCK with security decision and detector ID attribution | eports/evidence/ast-evasion.json | Tree-sitter native bindings | EXECUTED_PASS |
| **SEC-GATE-005** | CRITICAL | Egress socket IP pinning & DNS rebinding / TOCTOU protection | src/security/egress/egress-engine.ts, src/security/ip-utils.ts | 
pm test -- tests/security/egress-rebinding.test.ts | egress-rebinding.test.ts:EGRESS-001..005 | Socket connect abort, 403 Forbidden with EGRESS_BLOCKED | eports/evidence/egress-results.json | Network loopback isolation | EXECUTED_PASS |
| **SEC-GATE-006** | CRITICAL | Streaming DLP bounded memory & chunk-boundary secret sanitization | src/security/dlp/incremental-secret-scanner.ts | 
pm test -- tests/security/streaming-dlp-boundary.test.ts | streaming-dlp-boundary.test.ts:DLP-001..006 | Sliding window matches across boundary; zero raw secret in output | eports/evidence/dlp-benchmark.json | Constant heap bound (<10MB) | EXECUTED_PASS |
| **SEC-GATE-007** | CRITICAL | Remote enterprise intelligence circuit breaker & fail-closed fallback | src/security/intelligence-engine.ts, src/security/circuit-breaker.ts | 
pm test -- tests/security/circuit-breaker.test.ts | circuit-breaker.test.ts:CB-001..004 | High-risk calls fail-closed to BLOCK on remote timeout/outage | eports/evidence/circuit-breaker.json | Remote 500/timeout injection | EXECUTED_PASS |
| **SEC-GATE-008** | CRITICAL | Crown-jewel IP boundary: Zero proprietary corpora or secret weights in public npm | scripts/verify-ip-boundary.ts, package.json | 
px ts-node scripts/verify-ip-boundary.ts | erify-ip-boundary.ts:IP-BOUNDARY-GATE | Non-zero exit code on private repo references, weights, or corpora in tarball | eports/evidence/ip-boundary-scan.json | Clean build + npm pack | EXECUTED_PASS |
| **SEC-GATE-009** | CRITICAL | API key cryptographic verifier storage & constant-time validation | mcp-shield-licensing/src/lib/api-keys.ts | 	sx tests/api-key-verification.test.ts | pi-key-verification.test.ts:KEY-001..008 | 401 Unauthorized; prefix-only or mutated keys strictly rejected | eports/evidence/api-key-tests.json | Licensing workspace | EXECUTED_PASS |
| **SEC-GATE-010** | CRITICAL | Database-backed multi-tenant isolation & IDOR denial | mcp-shield-licensing/src/lib/authz.ts, supabase/migrations/ | 	sx tests/tenant-idor-authorization.test.ts | 	enant-idor-authorization.test.ts:IDOR-001..011 | 403 Forbidden / 404 Not Found on cross-tenant read, write, delete | eports/evidence/idor-suite.json | Schema & RLS verifier | EXECUTED_PASS |
| **SEC-GATE-011** | CRITICAL | Telemetry ingestion validation, bounded payload & structured redaction | mcp-shield-licensing/src/app/api/v1/telemetry/ingest/route.ts | 	sx tests/telemetry-ingestion.test.ts | 	elemetry-ingestion.test.ts:TELEM-001..006 | 400 on clock skew (>5m), 413 on payload (>1MB), secrets scrubbed | eports/evidence/telemetry-tests.json | Licensing workspace | EXECUTED_PASS |
| **SEC-GATE-012** | CRITICAL | Server-authoritative Stripe billing & durable webhook idempotency | mcp-shield-licensing/src/app/api/v1/billing/webhook/route.ts | 	sx tests/billing-idempotency.test.ts | illing-idempotency.test.ts:BILL-001..005 | Duplicate webhook returns 200 without duplicate state mutation | eports/evidence/billing-tests.json | Concurrency test runner | EXECUTED_PASS |
| **SEC-GATE-013** | CRITICAL | Cryptographic Ed25519 policy signing & anti-rollback verification | mcp-shield-licensing/src/app/api/v1/policy/sync/route.ts | 	sx tests/policy-signing-integrity.test.ts | policy-signing-integrity.test.ts:POL-001..006 | Tampered byte, expired policy, or version downgrade rejected | eports/evidence/policy-signing.json | Ed25519 keypair | EXECUTED_PASS |
| **SEC-GATE-014** | CRITICAL | Break-glass administration authorization & mandatory durable audit | mcp-shield-licensing/src/app/api/v1/admin/break-glass/route.ts | 	sx tests/break-glass-audit.test.ts | reak-glass-audit.test.ts:BG-001..004 | 401 on service key; failure to write audit log aborts operation | eports/evidence/break-glass-tests.json | Dedicated ADMIN_MASTER_KEY | EXECUTED_PASS |
| **SEC-GATE-015** | CRITICAL | Atomic database organization ownership transfer | mcp-shield-licensing/src/app/api/v1/organizations/[id]/transfer-owner/route.ts | 	sx tests/ownership-transfer.test.ts | ownership-transfer.test.ts:OWN-001..004 | Atomic transaction; guaranteed 1 owner, 0 double-owner or 0-owner | eports/evidence/ownership-tests.json | Database RPC test | EXECUTED_PASS |
| **SEC-GATE-016** | CRITICAL | Enterprise Intel fail-closed authentication & zero dynamic principals | mcp-shield-enterprise-intel/src/intel/auth.ts | 
ode tests/verify-intel.js | erify-intel.js:Test 2, 11, 12 | 401 Unauthorized; unknown keys rejected without env principal creation | eports/evidence/intel-test-log.txt | Intel workspace, port 4040 | EXECUTED_PASS |
| **SEC-GATE-017** | CRITICAL | Database schema integrity, constraint matching & RLS validation | mcp-shield-licensing/src/lib/schema-integrity.ts | 	sx tests/schema-integrity.test.ts | schema-integrity.test.ts:SCHEMA-001..004 | Non-zero exit on schema mismatch, missing RLS, or missing FKs | eports/evidence/schema-verification.json | PostgreSQL migration DDL | EXECUTED_PASS |
| **SEC-GATE-018** | CRITICAL | Attack-family coverage evaluated through real pipeline execution | scripts/attack-family-coverage-gate.ts | 
ode -r ts-node/register scripts/attack-family-coverage-gate.ts | ttack-family-coverage-gate.ts:RUN-GATE | 0 unconditional booleans; non-zero exit if any dimension unblocked | eports/evidence/attack-family-coverage.json | 10 families, 6 dimensions | EXECUTED_PASS |
| **SEC-GATE-019** | CRITICAL | Security regression gate evaluated against live attack corpus | scripts/security-regression-gate.ts | 
ode --expose-gc -r ts-node/register scripts/security-regression-gate.ts | security-regression-gate.ts:RUN-GATE | Evaluates decision against every attack; reports real host platform | security-report.json | Node 20+, --expose-gc | EXECUTED_PASS |
| **SEC-GATE-020** | HIGH | Release provenance consistency (package, lockfile, manifest) | scripts/generate-release-manifest.ts | 
px ts-node scripts/generate-release-manifest.ts | generate-release-manifest.ts:VERIFY-PROVENANCE | Non-zero exit code on version divergence across source and lockfile | eports/release-manifest.json | Git workspace | EXECUTED_PASS |
| **SEC-GATE-021** | HIGH | Minimal runtime container image (zero build compilers) | Dockerfile | powershell -Command scripts/verify-docker-hardening.ps1 | erify-docker-hardening.ps1:CONTAINER-GATE | Non-zero exit if gcc/g++/make/python3 are in production runner stage | eports/evidence/docker-audit.json | Dockerfile static analyzer | EXECUTED_PASS |
| **SEC-GATE-022** | HIGH | Real dashboard admin analytics (zero mock data) | cloud-dashboard/src/app/api/v1/admin/analytics/route.ts | 
pm test -- cloud-dashboard/tests/analytics-authenticity.test.ts | nalytics-authenticity.test.ts:ANALYTICS-001..003 | Queries database; returns empty state if 0 events, zero static mocks | eports/evidence/analytics-audit.json | Dashboard test runner | EXECUTED_PASS |
| **SEC-GATE-023** | HIGH | Security-critical mutation testing (zero surviving bypass mutants) | scripts/mutation-test-runner.ts | 
pm run test:mutations | mutation-test-runner.ts:OPERATORS-1..9 | Non-zero exit if mutation score < 95% or any critical bypass mutant survives | eports/evidence/mutation-results.json | AST mutation runner | EXECUTED_PASS |
| **SEC-GATE-024** | HIGH | Bounded memory retention & lifecycle safety (< 15MB delta over 10k req) | scripts/lifecycle-memory-benchmark.ts | 
pm test -- scripts/lifecycle-memory-benchmark.ts | lifecycle-memory-benchmark.ts:MEM-001 | Non-zero exit if heap growth exceeds 15 MB ceiling | eports/evidence/memory-benchmark.json | V8 garbage collection | EXECUTED_PASS |
| **SEC-GATE-025** | HIGH | Health vs readiness endpoint separation & zero secret disclosure | src/proxy/mcp-gateway.ts, licensing/src/app/api/health/route.ts | 
pm test -- tests/unit/health-readiness.test.ts | health-readiness.test.ts:HEALTH-001..003 | Readiness reports unready when dependencies down; never leaks secrets | eports/evidence/health-check.json | HTTP client | EXECUTED_PASS |
| **SEC-GATE-026** | MEDIUM | Supply chain audit & CycloneDX SBOM generation | package.json, package-lock.json | 
pm run sbom | cyclonedx-npm | Non-zero exit on unresolvable vulnerabilities or invalid lockfile | mcp-shield.sbom.json | CycloneDX CLI | EXECUTED_PASS |
| **SEC-GATE-027** | MEDIUM | Disaster recovery & automated backup reconciliation drill | scripts/disaster-recovery-drill.ts | 
pm run drill:dr | disaster-recovery-drill.ts:DR-001..005 | Non-zero exit if cryptographic replay or signature restoration fails | eports/evidence/dr-drill.json | Offline drill runner | EXECUTED_PASS |
| **SEC-GATE-028** | CRITICAL | Master ecosystem certification across all 3 repositories | scripts/ecosystem-certification-runner.ts | 
px ts-node scripts/ecosystem-certification-runner.ts | ecosystem-certification-runner.ts:CERT-ALL | Produces verified PRODUCTION_READY verdict strictly from executed evidence | eports/production-certification.json | All 3 repositories clean | EXECUTED_PASS |

---
*Generated by the MCP-Shield Security Architecture Team. All controls must execute cleanly to certify production readiness.*
