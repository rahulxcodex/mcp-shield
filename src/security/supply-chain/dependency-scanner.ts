import * as fs from 'fs';
import * as path from 'path';

export interface PackageVulnerability {
  ecosystem: 'npm' | 'pypi';
  packageName: string;
  installedVersion: string;
  vulnerabilityId: string; // e.g. CVE-2024-XXXX or GHSA-XXXX
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  affectedRange: string;
  recommendation: string;
}

export interface TypoSquatAlert {
  suspectPackage: string;
  targetLegitimatePackage: string;
  ecosystem: 'npm' | 'pypi';
  similarity: number; // 0 to 1
  reason: string;
}

export interface DependencyScanResult {
  totalDependenciesScanned: number;
  vulnerabilities: PackageVulnerability[];
  typoSquats: TypoSquatAlert[];
  riskSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// Known vulnerable advisory database baseline
const KNOWN_ADVISORIES: Array<{
  ecosystem: 'npm' | 'pypi';
  name: string;
  vulnerableVersions: string[]; // matching semver or version prefixes
  vulnId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  affectedRange: string;
  recommendation: string;
}> = [
  {
    ecosystem: 'npm',
    name: 'axios',
    vulnerableVersions: ['0.21.0', '0.21.1', '1.5.0', '1.6.0', '0.19.'],
    vulnId: 'CVE-2023-45857',
    severity: 'HIGH',
    title: 'Axios Cross-Site Request Forgery / SSRF in follow-redirects',
    affectedRange: '< 1.7.4',
    recommendation: 'Upgrade to axios >= 1.7.4',
  },
  {
    ecosystem: 'npm',
    name: 'express',
    vulnerableVersions: ['4.16.0', '4.17.0', '4.17.1', '4.18.0', '4.18.1', '4.18.2'],
    vulnId: 'CVE-2024-43796',
    severity: 'MEDIUM',
    title: 'Express Path Traversal via res.sendFile',
    affectedRange: '< 4.19.2',
    recommendation: 'Upgrade to express >= 4.19.2',
  },
  {
    ecosystem: 'npm',
    name: 'jsonwebtoken',
    vulnerableVersions: ['8.5.1', '9.0.0', '8.5.0'],
    vulnId: 'CVE-2022-23529',
    severity: 'CRITICAL',
    title: 'jsonwebtoken Insecure Key Retrieval Remote Code Execution',
    affectedRange: '<= 8.5.1',
    recommendation: 'Upgrade to jsonwebtoken >= 9.0.0 with secure secret callbacks',
  },
  {
    ecosystem: 'npm',
    name: 'lodash',
    vulnerableVersions: ['4.17.15', '4.17.19', '4.17.20'],
    vulnId: 'CVE-2021-23337',
    severity: 'HIGH',
    title: 'Lodash Command Injection / Prototype Pollution via template',
    affectedRange: '< 4.17.21',
    recommendation: 'Upgrade to lodash >= 4.17.21',
  },
  {
    ecosystem: 'pypi',
    name: 'urllib3',
    vulnerableVersions: ['1.26.17', '1.26.18', '2.0.6', '1.25.'],
    vulnId: 'CVE-2023-45803',
    severity: 'HIGH',
    title: 'urllib3 Request body leak on redirect',
    affectedRange: '< 2.0.7',
    recommendation: 'Upgrade to urllib3 >= 2.0.7',
  },
  {
    ecosystem: 'pypi',
    name: 'requests',
    vulnerableVersions: ['2.28.0', '2.28.1', '2.30.0', '2.31.0'],
    vulnId: 'CVE-2023-32681',
    severity: 'MEDIUM',
    title: 'Requests unintended leak of Proxy-Authorization header',
    affectedRange: '< 2.32.0',
    recommendation: 'Upgrade to requests >= 2.32.0',
  },
];

// Popular target packages that malware and attackers commonly typo-squat in agent/MCP ecosystem
const CANONICAL_MCP_PACKAGES: string[] = [
  '@modelcontextprotocol/sdk',
  '@modelcontextprotocol/server',
  '@modelcontextprotocol/client',
  'mcp-shield',
  'mcpshld',
  'express',
  'axios',
  'dotenv',
  'zod',
  'fastapi',
  'uvicorn',
  'langchain',
];

export class DependencyVulnerabilityScanner {
  /**
   * Scans a target directory for vulnerable npm and PyPI dependencies and typo-squat attacks.
   */
  public scanDirectory(dirPath: string): DependencyScanResult {
    const vulns: PackageVulnerability[] = [];
    const typoSquats: TypoSquatAlert[] = [];
    let depCount = 0;

    // 1. Scan package.json
    const packageJsonPath = path.join(dirPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const raw = fs.readFileSync(packageJsonPath, 'utf8');
        const pkg = JSON.parse(raw);
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };

        for (const [name, verStr] of Object.entries(allDeps)) {
          depCount++;
          const cleanVer = String(verStr).replace(/^[\^~>=<]/, '');
          this.checkVulnerabilities('npm', name, cleanVer, vulns);
          this.checkTypoSquat('npm', name, typoSquats);
        }
      } catch {}
    }

    // 2. Scan Python requirements.txt
    const reqPath = path.join(dirPath, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      try {
        const raw = fs.readFileSync(reqPath, 'utf8');
        const lines = raw.split(/\r?\n/);
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)(?:[=><~]+([0-9\.\w]+))?/);
          if (match) {
            depCount++;
            const name = match[1];
            const ver = match[2] || '0.0.0';
            this.checkVulnerabilities('pypi', name, ver, vulns);
            this.checkTypoSquat('pypi', name, typoSquats);
          }
        }
      } catch {}
    }

    // 3. Scan pyproject.toml if present
    const pyprojectPath = path.join(dirPath, 'pyproject.toml');
    if (fs.existsSync(pyprojectPath)) {
      try {
        const raw = fs.readFileSync(pyprojectPath, 'utf8');
        const lines = raw.split(/\r?\n/);
        for (const line of lines) {
          const match = line.match(/^\s*["']?([a-zA-Z0-9_\-\.]+)["']?\s*=\s*["']([^"']+)["']/);
          if (match) {
            depCount++;
            const name = match[1];
            const ver = match[2].replace(/^[\^~>=<]/, '');
            this.checkVulnerabilities('pypi', name, ver, vulns);
            this.checkTypoSquat('pypi', name, typoSquats);
          }
        }
      } catch {}
    }

    const riskSummary = {
      critical: vulns.filter(v => v.severity === 'CRITICAL').length,
      high: vulns.filter(v => v.severity === 'HIGH').length,
      medium: vulns.filter(v => v.severity === 'MEDIUM').length,
      low: vulns.filter(v => v.severity === 'LOW').length,
    };

    return {
      totalDependenciesScanned: depCount,
      vulnerabilities: vulns,
      typoSquats,
      riskSummary,
    };
  }

  private checkVulnerabilities(
    ecosystem: 'npm' | 'pypi',
    name: string,
    version: string,
    results: PackageVulnerability[]
  ): void {
    const matches = KNOWN_ADVISORIES.filter(
      a => a.ecosystem === ecosystem && a.name.toLowerCase() === name.toLowerCase()
    );

    for (const match of matches) {
      const isVulnerable = match.vulnerableVersions.some(v => version.startsWith(v));
      if (isVulnerable) {
        results.push({
          ecosystem,
          packageName: name,
          installedVersion: version,
          vulnerabilityId: match.vulnId,
          severity: match.severity,
          title: match.title,
          affectedRange: match.affectedRange,
          recommendation: match.recommendation,
        });
      }
    }
  }

  private checkTypoSquat(
    ecosystem: 'npm' | 'pypi',
    candidate: string,
    results: TypoSquatAlert[]
  ): void {
    const lowerCandidate = candidate.toLowerCase();
    for (const target of CANONICAL_MCP_PACKAGES) {
      const lowerTarget = target.toLowerCase();
      if (lowerCandidate === lowerTarget) continue;

      const sim = this.levenshteinSimilarity(lowerCandidate, lowerTarget);
      // High similarity (> 0.8) or common character substitutions (1 for l, 0 for o)
      const hasSubstitutions =
        lowerCandidate.replace(/1/g, 'l').replace(/0/g, 'o') === lowerTarget;

      if ((sim >= 0.82 && sim < 1.0) || hasSubstitutions) {
        results.push({
          suspectPackage: candidate,
          targetLegitimatePackage: target,
          ecosystem,
          similarity: Number(sim.toFixed(2)),
          reason: hasSubstitutions
            ? `Character homoglyph substitution targeting "${target}"`
            : `Suspiciously high edit distance similarity to trusted package "${target}"`,
        });
      }
    }
  }

  private levenshteinSimilarity(s1: string, s2: string): number {
    const m = s1.length;
    const n = s2.length;
    if (m === 0) return n === 0 ? 1 : 0;
    if (n === 0) return 0;

    const d: number[][] = [];
    for (let i = 0; i <= m; i++) {
      d[i] = [i];
    }
    for (let j = 0; j <= n; j++) {
      d[0][j] = j;
    }

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,
          d[i][j - 1] + 1,
          d[i - 1][j - 1] + cost
        );
      }
    }

    const maxLen = Math.max(m, n);
    return 1 - d[m][n] / maxLen;
  }
}
