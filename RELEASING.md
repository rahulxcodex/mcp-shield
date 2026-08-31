# Release Engineering & Publishing Guide 🚀

This document outlines the release process, versioning standards, supply-chain security controls, and verification steps for publishing new releases of **MCP-Shield**.

---

## 🏷️ Versioning Policy

MCP-Shield adheres to [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR (`x.0.0`)**: Incompatible API breaks, major policy schema overhauls, or breaking CLI changes.
- **MINOR (`1.x.0`)**: Backwards-compatible new features, new security detection modules, or new client auto-discovery plugins.
- **PATCH (`1.0.x`)**: Backwards-compatible security fixes, parser optimizations, and bug remediations.

---

## 🔒 Supply-Chain Security & Provenance

Every official release published through our automated pipeline enforces:

1. **GitHub Actions OpenID Connect (OIDC)**: Cryptographically verified publishing to npm without persistent long-lived tokens.
2. **Build Provenance**: Verified attestation generated via `--provenance` linking the published package to the exact git commit and GitHub workflow run.
3. **CycloneDX Software Bill of Materials (SBOM)**: Machine-readable `sbom.json` generated and attached to each GitHub Release.
4. **Automated CI Hardening**: CI workflows run through StepSecurity Harden Runner to audit egress traffic and prevent runner tampering.

---

## 📋 Release Checklist

### Step 1: Pre-Release Verification

Run the complete test and audit suites locally before cutting a release:

```bash
# Ensure working directory is clean
git status

# Verify type safety and build
npm run typecheck
npm run build

# Run all test suites, red-team challenges, and fuzzers
npm test
npm run test:redteam
npm run fuzz
npm run bench
```

### Step 2: Bump Version

Update the version field in `package.json`:

```bash
# For a patch release
npm version patch --no-git-tag-version

# For a minor release
npm version minor --no-git-tag-version

# For a major release
npm version major --no-git-tag-version
```

### Step 3: Commit and Tag

Commit the version change and create a signed git tag:

```bash
VERSION="v$(node -p "require('./package.json').version")"
git add package.json
git commit -m "chore: release ${VERSION}"
git tag -a "${VERSION}" -m "Release ${VERSION}"
```

### Step 4: Push to GitHub

Push the commit and tag to trigger the automated GitHub Actions release workflow:

```bash
git push origin main
git push origin "${VERSION}"
```

### Step 5: Automated Workflow Execution

The `.github/workflows/release.yml` workflow automatically:
1. Checks out the tagged commit.
2. Compiles TypeScript production artifacts (`npm run build`).
3. Generates a CycloneDX `sbom.json`.
4. Publishes to npm with cryptographic `--provenance`.
5. Creates a GitHub Release with the attached SBOM.

---

## 🔍 Post-Release Verification

Verify that the newly published package is live on the npm registry:

```bash
# Query npm registry
npm view mcp-shield version

# Test global execution via npx
npx mcp-shield@latest --help
```

---

## 🚑 Hotfix & Rollback Policy

In the event of a critical regression or severe vulnerability introduced in a release:

1. **Unpublish Policy**: Never delete an existing npm release to prevent downstream breakage.
2. **Deprecation**: Mark the vulnerable version as deprecated:
   ```bash
   npm deprecate mcp-shield@<version> "Critical vulnerability detected. Please upgrade to latest."
   ```
3. **Emergency Hotfix**: Branch off the affected tag (`hotfix/1.0.x`), apply the patch, and publish an immediate PATCH increment (`v1.0.x+1`).
