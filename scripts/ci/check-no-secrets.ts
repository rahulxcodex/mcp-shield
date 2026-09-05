import * as fs from 'fs';
import * as path from 'path';

console.log('\n============================================================');
console.log(' RUNNING TARGETED SECRET & CREDENTIAL SCANNER (CI GATE)');
console.log('============================================================\n');

const ROOT_DIR = path.resolve(__dirname, '../..');

interface Rule {
  name: string;
  pattern: RegExp;
  allowedFiles?: string[];
}

const FORBIDDEN_RULES: Rule[] = [
  {
    name: 'Hardcoded developer personal email',
    pattern: /rahulsahygupta24@gmail\.com/i,
  },
  {
    name: 'Deprecated client-side master elevation cookie',
    pattern: /mcp_master_elevated/i,
    allowedFiles: [
      'scripts/ci/check-no-secrets.ts',
      'scripts/test-customer-agents.js',
    ],
  },
  {
    name: 'Specific Supabase project reference',
    pattern: /magfptvxgxscmlzphhlq/i,
    allowedFiles: ['scripts/ci/check-no-secrets.ts'],
  },
  {
    name: 'Hardcoded live production secret key token',
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{40,}/,
    allowedFiles: [
      'scripts/ci/check-no-secrets.ts',
      'tests/redteam/black-box-independent.test.ts',
    ],
  },
];

const IGNORE_DIR_NAMES = [
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  'coverage',
  '.data',
  'scratch',
  '.vercel',
  '.turbo',
];

const IGNORE_FILES = [
  'package-lock.json',
  'mcp-shield.sbom.json',
];

function scanDirectory(dir: string, violations: Array<{ file: string; line: number; rule: string }>): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORE_DIR_NAMES.includes(entry.name)) {
        continue;
      }
      scanDirectory(path.join(dir, entry.name), violations);
      continue;
    }

    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/');

    if (IGNORE_FILES.includes(entry.name) || entry.name.endsWith('.png') || entry.name.endsWith('.joblib')) {
      continue;
    }

    // Only scan text / code files
    if (!/\.(ts|tsx|js|jsx|json|md|sql|py|html|env\.example)$/i.test(entry.name)) {
      continue;
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      for (const rule of FORBIDDEN_RULES) {
        if (rule.allowedFiles && rule.allowedFiles.some((f) => relativePath === f || relativePath.endsWith(f))) {
          continue;
        }

        if (rule.pattern.test(lineText)) {
          violations.push({
            file: relativePath,
            line: i + 1,
            rule: rule.name,
          });
        }
      }
    }
  }
}

function runCheck(): void {
  const violations: Array<{ file: string; line: number; rule: string }> = [];
  scanDirectory(ROOT_DIR, violations);

  if (violations.length > 0) {
    console.error(`FAILED: Found ${violations.length} secret/hygiene violations:`);
    for (const v of violations) {
      console.error(`  - [${v.rule}] at ${v.file}:${v.line}`);
    }
    process.exit(1);
  }

  console.log('PASS: Targeted secret scanner verified 0 leaked secrets or forbidden patterns across codebase.');
  console.log('\n------------------------------------------------------------');
  console.log(' ALL SECRET SCANNING & CREDENTIAL HYGIENE CHECKS PASSED');
  console.log('------------------------------------------------------------\n');
}

runCheck();
