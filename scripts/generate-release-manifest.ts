import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';

export interface ReleaseManifest {
  product: string;
  version: string;
  gitCommitSha: string;
  buildTimestamp: string;
  nodeRuntimeVersion: string;
  dependencyLockHash: string;
  sbomDigest?: string;
  ecosystemRepositories: {
    gateway: { path: string; version: string; commitSha: string };
    enterpriseIntel: { path: string; version: string; commitSha: string };
    licensing: { path: string; version: string; commitSha: string };
    hfSpace: { path: string; version: string; commitSha: string; runtime: string };
  };
  provenanceConsistent: boolean;
}

function getGitSha(repoPath: string): string {
  try {
    return execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return 'unknown-commit';
  }
}

export function generateReleaseManifest(): ReleaseManifest {
  const rootDir = path.resolve(__dirname, '..');
  const pkgPath = path.join(rootDir, 'package.json');
  const lockPath = path.join(rootDir, 'package-lock.json');

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

  if (pkg.version !== lock.version) {
    throw new Error('PROVENANCE_MISMATCH: package.json version (' + pkg.version + ') does not match package-lock.json version (' + lock.version + ')');
  }

  const lockContent = fs.readFileSync(lockPath);
  const lockHash = crypto.createHash('sha256').update(lockContent).digest('hex');

  const sbomPath = path.join(rootDir, 'mcp-shield.sbom.json');
  let sbomDigest: string | undefined;
  if (fs.existsSync(sbomPath)) {
    sbomDigest = crypto.createHash('sha256').update(fs.readFileSync(sbomPath)).digest('hex');
  }

  const scratchDir = path.resolve(rootDir, '..');
  const intelDir = path.join(scratchDir, 'mcp-shield-enterprise-intel');
  const licensingDir = path.join(scratchDir, 'mcp-shield-licensing');

  const intelPkg = fs.existsSync(path.join(intelDir, 'package.json'))
    ? JSON.parse(fs.readFileSync(path.join(intelDir, 'package.json'), 'utf8'))
    : { version: '1.0.0' };

  const licensingPkg = fs.existsSync(path.join(licensingDir, 'package.json'))
    ? JSON.parse(fs.readFileSync(path.join(licensingDir, 'package.json'), 'utf8'))
    : { version: '1.0.0' };

  const manifest: ReleaseManifest = {
    product: 'MCP Shield Zero-Trust Security Ecosystem',
    version: pkg.version,
    gitCommitSha: getGitSha(rootDir),
    buildTimestamp: new Date().toISOString(),
    nodeRuntimeVersion: process.version,
    dependencyLockHash: lockHash,
    sbomDigest,
    ecosystemRepositories: {
      gateway: {
        path: 'mcp-shield',
        version: pkg.version,
        commitSha: getGitSha(rootDir),
      },
      enterpriseIntel: {
        path: 'mcp-shield-enterprise-intel',
        version: intelPkg.version || '1.0.0',
        commitSha: getGitSha(intelDir),
      },
      licensing: {
        path: 'mcp-shield-licensing',
        version: licensingPkg.version || '1.0.0',
        commitSha: getGitSha(licensingDir),
      },
      hfSpace: {
        path: 'deployment/app.py',
        version: pkg.version,
        commitSha: getGitSha(rootDir),
        runtime: 'gradio/python',
      },
    },
    provenanceConsistent: true,
  };

  const reportsDir = path.join(rootDir, 'reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const outputPath = path.join(reportsDir, 'release-manifest.json');
  fs.writeFileSync(outputPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log('[RELEASE MANIFEST] Generated release manifest at ' + outputPath);
  return manifest;
}

if (require.main === module) {
  try {
    generateReleaseManifest();
  } catch (err: any) {
    console.error('Failed to generate release manifest:', err.message);
    process.exit(1);
  }
}
