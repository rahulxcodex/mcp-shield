const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const jestBin = path.resolve(__dirname, '../node_modules/jest/bin/jest.js');
const args = process.argv.slice(2);

console.log(`[TEST RUNNER] Executing Jest on Node ${process.version} (${process.platform})...`);

const result = spawnSync(process.execPath, ['--expose-gc', jestBin, '--runInBand', '--verbose', ...args], {
  cwd: path.resolve(__dirname, '..'),
  env: process.env,
  stdio: 'inherit'
});

if (result.status !== 0) {
  console.error(`[TEST RUNNER] Jest failed with exit code ${result.status}`);
  process.exit(result.status || 1);
}
