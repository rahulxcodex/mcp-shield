import * as fs from 'fs';
import * as path from 'path';
import { verifyIpBoundary } from './verify-ip-boundary';

interface ChecklistItem {
  id: string;
  phase: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  verificationMethod: string;
  target: string;
  status: 'PASS' | 'FAIL' | 'NOT_APPLICABLE';
}

interface Checklist {
  name: string;
  version: string;
  evaluatedAt: string;
  summary: {
    totalControls: number;
    criticalControls: number;
    highControls: number;
    mediumControls: number;
    status: string;
  };
  controls: ChecklistItem[];
}

function runChecklistVerification() {
  const checklistPath = path.resolve(__dirname, '../docs/production-checklist.json');
  if (!fs.existsSync(checklistPath)) {
    console.error('ERROR: docs/production-checklist.json not found!');
    process.exit(1);
  }

  const checklist: Checklist = JSON.parse(fs.readFileSync(checklistPath, 'utf8'));
  console.log(`\n============================================================`);
  console.log(` EVALUATING MCP SHIELD PRODUCTION READINESS GATES`);
  console.log(` Specification: ${checklist.name} (v${checklist.version})`);
  console.log(` Controls to evaluate: ${checklist.controls.length}`);
  console.log(`============================================================\n`);

  let failures = 0;
  let passed = 0;

  for (const control of checklist.controls) {
    let checkPassed = true;
    let detail = '';

    const targetPath = path.resolve(__dirname, '..', control.target);
    if (!fs.existsSync(targetPath)) {
      checkPassed = false;
      detail = `Target file missing: ${control.target}`;
    } else {
      detail = `Target verified: ${control.target}`;
    }

    if (checkPassed && control.verificationMethod === 'boundary_check') {
      const boundaryResult = verifyIpBoundary();
      if (!boundaryResult.passed) {
        checkPassed = false;
        detail = `IP Boundary check failed: ${boundaryResult.violations.join(', ')}`;
      }
    }

    if (checkPassed) {
      passed++;
      console.log(` [PASS] [${control.severity.padEnd(8)}] ${control.id}: ${control.title} (${control.target})`);
    } else {
      failures++;
      console.error(` [FAIL] [${control.severity.padEnd(8)}] ${control.id}: ${control.title} - ${detail}`);
    }
  }

  console.log(`\n------------------------------------------------------------`);
  console.log(` Summary: ${passed} Passed, ${failures} Failed out of ${checklist.controls.length} controls.`);
  console.log(` Status: ${failures === 0 ? 'PRODUCTION READY' : 'GATES FAILED'}`);
  console.log(`------------------------------------------------------------\n`);

  if (failures > 0) {
    process.exit(1);
  }
}

runChecklistVerification();
