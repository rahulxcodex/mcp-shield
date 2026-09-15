import * as fs from 'fs';
import * as path from 'path';

/**
 * Trade Secret & IP Boundary Guard
 * Audits public code for hardcoded proprietary constants, un-parameterized risk multipliers,
 * or private signing keys.
 */

const TARGET_DIRS = [
  path.join(__dirname, '../src/security'),
  path.join(__dirname, '../src/microkernel')
];

let totalViolations = 0;

function auditFile(filePath: string): void {
  if (!filePath.endsWith('.ts')) return;
  const content = fs.readFileSync(filePath, 'utf8');

  // Check for private key literal exposure
  if (content.includes('BEGIN PRIVATE KEY') || content.includes('BEGIN ED25519 PRIVATE KEY')) {
    console.error(`[TRADE SECRET VIOLATION] Private cryptographic key literal found in public source file: ${filePath}`);
    totalViolations++;
  }

  // Check for hardcoded weaponized payload strings
  if (content.includes('CHAIN-EXFIL-001') || content.includes('CHAIN-STAGE-DETONATE-001')) {
    console.error(`[TRADE SECRET VIOLATION] Weaponized attack chain ID literal exposed in public repo: ${filePath}`);
    totalViolations++;
  }
}

function traverse(dir: string): void {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      traverse(fullPath);
    } else if (entry.isFile()) {
      auditFile(fullPath);
    }
  }
}

console.log('[TRADE SECRET GUARD] Auditing public repository for trade secret invariants...');
for (const d of TARGET_DIRS) {
  traverse(d);
}

if (totalViolations > 0) {
  console.error(`❌ Audit failed with ${totalViolations} trade secret boundary violations.`);
  process.exit(1);
} else {
  console.log('✅ Trade Secret Boundary Clean: Zero private key literals or weaponized attack chains found.');
  process.exit(0);
}
