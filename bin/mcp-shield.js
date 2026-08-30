#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const distEntry = path.join(__dirname, '..', 'dist', 'index.js');

if (fs.existsSync(distEntry)) {
  require(distEntry);
} else {
  require('ts-node').register();
  require(path.join(__dirname, '..', 'src', 'index.ts'));
}
