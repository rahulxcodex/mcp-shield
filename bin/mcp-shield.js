#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const distEntry = path.join(__dirname, '..', 'dist', 'cli.js');

if (fs.existsSync(distEntry)) {
  const { runCli } = require(distEntry);
  runCli();
} else {
  require('ts-node').register();
  const { runCli } = require(path.join(__dirname, '..', 'src', 'cli.ts'));
  runCli();
}
