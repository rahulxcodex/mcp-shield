import * as fs from 'fs';
import * as path from 'path';

console.log('\n============================================================');
console.log(' VERIFYING NATIVE DEPENDENCIES & SUPPLY CHAIN INTEGRITY');
console.log('============================================================\n');

const NATIVE_DEPENDENCIES = ['tree-sitter', 'tree-sitter-bash'];

function verifyNativeDependencies(): void {
  const rootDir = path.resolve(__dirname, '../..');
  const pkgPath = path.join(rootDir, 'package.json');
  const lockPath = path.join(rootDir, 'package-lock.json');

  if (!fs.existsSync(pkgPath)) {
    throw new Error('package.json missing at ' + pkgPath);
  }
  if (!fs.existsSync(lockPath)) {
    throw new Error('package-lock.json missing at ' + lockPath);
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

  const errors: string[] = [];

  for (const dep of NATIVE_DEPENDENCIES) {
    const pkgVersion = pkg.dependencies?.[dep] || pkg.devDependencies?.[dep];
    if (!pkgVersion) {
      errors.push(`Native dependency '${dep}' is not declared in package.json dependencies.`);
      continue;
    }

    // Must be exact pinned version (no ^, ~, >, <, *, or latest)
    if (/[\^~><*]/.test(pkgVersion) || pkgVersion === 'latest') {
      errors.push(`Native dependency '${dep}' has unpinned/floating version '${pkgVersion}'. Must be exact pinned version.`);
      continue;
    }

    // Verify package-lock.json packages entry
    const lockEntry = lock.packages?.[`node_modules/${dep}`] || lock.dependencies?.[dep];
    if (!lockEntry) {
      errors.push(`Native dependency '${dep}' missing from package-lock.json.`);
      continue;
    }

    const lockVersion = lockEntry.version;
    if (lockVersion !== pkgVersion) {
      errors.push(`Native dependency '${dep}' version mismatch: package.json=${pkgVersion} vs package-lock.json=${lockVersion}.`);
    }

    if (!lockEntry.integrity) {
      errors.push(`Native dependency '${dep}' missing cryptographic integrity hash in package-lock.json.`);
    }

    console.log(`PASS: [NATIVE-DEP] '${dep}' is strictly pinned to ${pkgVersion} (integrity: ${lockEntry.integrity ? 'verified' : 'missing'})`);
  }

  if (errors.length > 0) {
    console.error('\nNative Dependency Violations:');
    for (const err of errors) {
      console.error(' - ' + err);
    }
    process.exit(1);
  }

  console.log('\n------------------------------------------------------------');
  console.log(' ALL NATIVE DEPENDENCIES & SUPPLY CHAIN CHECKS PASSED');
  console.log('------------------------------------------------------------\n');
}

verifyNativeDependencies();
