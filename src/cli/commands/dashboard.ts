import { Command } from 'commander';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export const dashboardCmd = new Command('dashboard')
  .description('Launch the local Enterprise Control Plane (Dashboard)')
  .option('-p, --port <number>', 'Port to run the dashboard on', '3000')
  .action((options) => {
    // Resolve path to the cloud-dashboard directory relative to this file
    // In dev: src/cli/commands/dashboard.ts -> ../../../cloud-dashboard
    // In prod: dist/cli/commands/dashboard.js -> ../../../cloud-dashboard
    const dashboardDir = path.resolve(__dirname, '../../../cloud-dashboard');

    if (!fs.existsSync(dashboardDir)) {
      console.error(`\x1b[31m[ERROR]\x1b[0m Dashboard directory not found at: ${dashboardDir}`);
      console.error('Make sure you have installed the full enterprise package.');
      process.exit(1);
    }

    console.log(`\x1b[36m[INFO]\x1b[0m Booting Enterprise Dashboard on port ${options.port}...`);
    
    // We run next dev or next start depending on environment. For simplicity, we use npm run dev.
    const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    
    const child = spawn(npmCmd, ['run', 'dev', '--', '-p', options.port], {
      cwd: dashboardDir,
      stdio: 'inherit',
      env: { ...process.env, PORT: options.port }
    });

    child.on('error', (err) => {
      console.error('\x1b[31m[ERROR]\x1b[0m Failed to start dashboard:', err);
    });

    child.on('exit', (code) => {
      if (code !== 0) {
        console.error(`\x1b[31m[ERROR]\x1b[0m Dashboard process exited with code ${code}`);
      }
    });
  });
