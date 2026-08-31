# Release Engineering & Publishing Guide 🚀

This document outlines the release process, versioning standards, supply-chain security controls, and verification steps for publishing new releases of **MCP-Shield**.

---

## 🏷️ Versioning Policy

MCP-Shield adheres to [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR (`x.0.0`)**: Incompatible API breaks, major policy schema overhauls, or breaking CLI changes.
- **MINOR (`1.x.0`)**: Backwards-compatible new features, new security detection modules, or new client auto-discovery plugins.
- **PATCH (`1.0.x`)**: Backwards-compatible security fixes, parser optimizations, and bug remediations.

---

## 🔒 Supply-Chain Security & Release Assurance

Every official release published through our automated pipeline enforces:

1. **Cryptographically Signed Commits & Tags**: All release tags and commits must be signed using GPG (`git tag -s`) or SSH (`git tag -u <key_id>`) to guarantee author identity.
2. **GitHub Actions OpenID Connect (OIDC)**: Cryptographically verified publishing to npm without persistent long-lived tokens via trusted publishing.
3. **Build Provenance**: Verified attestation generated via `npm publish --provenance` linking the published package to the exact git commit, builder, and GitHub workflow run.
4. **CycloneDX Software Bill of Materials (SBOM)**: Machine-readable `mcp-shield.sbom.json` generated using `@cyclonedx/cyclonedx-npm` and attached to each GitHub Release.
5. **Reproducible Automated Pipeline**: Only GitHub Actions CI publishes releases. Direct developer publishes to npm are blocked by policy.
6. **Pinned Actions & Dependency Scanning**: All GitHub Action steps are pinned to immutable 40-character commit SHAs. Pull requests are gated by Dependabot and GitHub Dependency Review.
7. **Multi-OS Native Matrix**: All releases pass comprehensive test suites and security corpora across both `ubuntu-latest` and `windows-latest` (Node 20.x, 22.x).

---

## 📋 Release Checklist

### Step 1: Pre-Release Verification

Run the complete test, security corpora, and fuzzing suites locally:

```bash
# Ensure working directory is clean
git status

# Verify type safety and build
npm run typecheck
npm run build

# Run all test suites, Windows adversarial corpora, red-team challenges, and fuzzers
npm test
npm run test:redteam
npm run fuzz
npm run sbom
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

### Step 3: Commit and Create Signed Tag

Commit the version change and create a cryptographically signed git tag:

```bash
VERSION="v$(node -p "require('./package.json').version")"
git add package.json package-lock.json
git commit -S -m "chore: release ${VERSION}"
git tag -s "${VERSION}" -m "Release ${VERSION}"
```

### Step 4: Push to GitHub

Push the commit and signed tag to trigger the automated GitHub Actions release workflow:

```bash
git push origin main
git push origin "${VERSION}"
```

### Step 5: Automated Workflow Execution

The `.github/workflows/release.yml` workflow automatically:
1. Hardens the runner environment with StepSecurity.
2. Checks out the tagged commit with full git history.
3. Performs a clean build and runs the full test suite + security corpora.
4. Generates a CycloneDX Software Bill of Materials (`mcp-shield.sbom.json`).
5. Generates the package tarball (`mcp-shield-*.tgz`).
6. Publishes to npm with cryptographic `--provenance` via OIDC.
7. Creates a signed GitHub Release attaching the SBOM and tarball package.

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
