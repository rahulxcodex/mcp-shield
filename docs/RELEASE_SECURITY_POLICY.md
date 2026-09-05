# MCP-Shield — Release Security Policy & Provenance Invariants

## 1. Zero-Defect Release Gate Mandate
A release of mcp-shield (or related private packages) may NOT be published or certified unless all of the following conditions are simultaneously met:
1. **Clean Clean-Room Build**: Build succeeds without warnings or reliance on uncommitted files.
2. **Provenance Agreement**: Version in package.json, package-lock.json, git tag, release manifest, and SBOM must agree exactly.
3. **IP Boundary Clean**: 
pm pack tarball contains zero trade secrets, proprietary corpora, or private signing keys.
4. **Mandatory Security Gates**:
   - Security Regression Gate (scripts/security-regression-gate.ts): All attacks evaluated against live detectors and verified blocked.
   - Attack Coverage Gate (scripts/attack-family-coverage-gate.ts): 100% of attack families across all 6 dimensions evaluated through real pipeline execution (0 unconditional booleans).
   - Mutation Resilience Gate (scripts/mutation-test-runner.ts): Mutation score $\ge 95\%$ with 0 surviving bypass mutants.
   - Multi-Tenant IDOR Integration Gate: Real PostgreSQL/Supabase schema and RLS policies verified.
   - Fail-Closed Secret Invariant: Zero production credential fallbacks or hardcoded administrative accounts.

---

## 2. Supply-Chain & Build Verification
- **Immutable Action Pinning**: Security-critical GitHub Actions in .github/workflows/ must be pinned to full 40-character commit SHAs.
- **Dependency Audit**: 
pm audit signatures and 
pm audit --omit=dev must report zero critical or high vulnerabilities.
- **SBOM Generation**: A CycloneDX SBOM (mcp-shield.sbom.json) must be created at build time and hashed in eports/release-manifest.json.

---

## 3. Certification Report
Every release must generate an immutable, machine-readable certification report:
eports/production-certification.json
containing exact test execution timestamps, git commit SHA, control counts, and individual execution statuses.

---
*Maintained by the MCP-Shield Release Engineering & Security Architecture Board.*
