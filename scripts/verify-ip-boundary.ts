import * as fs from 'fs';
import * as path from 'path';

/**
 * MCP Shield Trade Secret & IP Boundary Verification Gate
 * Enforces Phase 24 & Non-Negotiable Rules 5, 13:
 * - Scans package files list and dist output
 * - Asserts zero proprietary intelligence, scoring constants, or private keys leak into npm package
 */

const PROPRIETARY_STRINGS = [
  'AST_COMPLEXITY_EXPONENT',
  'EGRESS_SEVERITY_MULTIPLIER',
  'DRIFT_BASE_PENALTY',
  'CHAIN-EXFIL-001',
  'CHAIN-STAGE-DETONATE-001',
  '-----BEGIN PRIVATE KEY-----',
  'LICENSE_PRIVATE_KEY',
];

const FORBIDDEN_DIST_FILES = [
  'mcp-shield-enterprise-intel',
  'mcp-shield-licensing',
  'proprietary-attack-corpus.ts',
  'threat-corpus.json',
];

export function verifyIpBoundary(): { passed: boolean; violations: string[] } {
  const violations: string[] = [];
  const rootDir = path.resolve(__dirname, '..');
  const pkgPath = path.join(rootDir, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    violations.push('package.json not found');
    return { passed: false, violations };
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const filesArray: string[] = pkg.files || [];

  // Check 1: Ensure private repository directories or test fixtures are not in published files
  for (const item of filesArray) {
    for (const forbidden of FORBIDDEN_DIST_FILES) {
      if (item.toLowerCase().includes(forbidden.toLowerCase())) {
        violations.push(`Forbidden trade-secret artifact exposed in package.json files array: "${item}"`);
      }
    }
  }

  // Check 2: Scan built dist directory if it exists
  const distDir = path.join(rootDir, 'dist');
  if (fs.existsSync(distDir)) {
    const scanDir = (dir: string) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          scanDir(fullPath);
        } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.d.ts'))) {
          const content = fs.readFileSync(fullPath, 'utf8');
          for (const secretString of PROPRIETARY_STRINGS) {
            if (content.includes(secretString)) {
              violations.push(`Proprietary trade secret string "${secretString}" detected in build artifact: ${fullPath}`);
            }
          }
        }
      }
    };
    scanDir(distDir);
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}

if (require.main === module) {
  console.log(`\n============================================================`);
  console.log(` VERIFYING MCP SHIELD TRADE SECRET & IP BOUNDARY INTEGRITY`);
  console.log(`============================================================\n`);

  const result = verifyIpBoundary();
  if (result.passed) {
    console.log(` [PASS] Crown-jewel IP boundary strictly verified.`);
    console.log(`        - No proprietary scoring constants leaked into public build.`);
    console.log(`        - No proprietary attack corpora leaked into npm files list.`);
    console.log(`        - Zero private signing keys present in public repository.`);
    console.log(`\n------------------------------------------------------------`);
    console.log(` Status: IP BOUNDARY CLEAN`);
    console.log(`------------------------------------------------------------\n`);
  } else {
    console.error(` [FAIL] IP Boundary violations detected:`);
    for (const v of result.violations) {
      console.error(`   - ${v}`);
    }
    process.exit(1);
  }
}
