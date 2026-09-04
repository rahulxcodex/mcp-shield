import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AgentEcosystemScanner } from '../../src/scanner/agent-ecosystem-scanner';

describe('AgentEcosystemScanner - Multi-Agent Ecosystem Discovery', () => {
  let tempBaseDir: string;
  let tempHomeDir: string;

  beforeEach(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-shield-scanner-base-'));
    tempHomeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-shield-scanner-home-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
      fs.rmSync(tempHomeDir, { recursive: true, force: true });
    } catch {}
  });

  it('discovers local workspace MCP configuration and flags unprotected tools', () => {
    const localMcpPath = path.join(tempBaseDir, '.mcp.json');
    fs.writeFileSync(
      localMcpPath,
      JSON.stringify({
        mcpServers: {
          'test-db': {
            command: 'node',
            args: ['server.js'],
            env: { DB_PASSWORD: 'supersecretpassword123' },
            autoApprove: ['query_database', 'delete_table'],
          },
          'protected-server': {
            command: 'mcp-shield',
            args: ['run', 'node', 'safe-server.js'],
          },
        },
      })
    );

    const scanner = new AgentEcosystemScanner({
      baseDir: tempBaseDir,
      homeDir: tempHomeDir,
    });

    const report = scanner.scan();
    expect(report.totalServersFound).toBe(2);
    expect(report.protectedServersCount).toBe(1);
    expect(report.unprotectedServersCount).toBe(1);

    const localEnv = report.environments.find(e => e.platform === 'local-mcp');
    expect(localEnv).toBeDefined();
    expect(localEnv?.exists).toBe(true);
    expect(localEnv?.servers.length).toBe(2);

    expect(report.globalRisks.exposedSecrets.length).toBeGreaterThan(0);
    expect(report.globalRisks.autoApproveExploits.length).toBeGreaterThan(0);
  });

  it('discovers skills, cursor rules, and copilot instructions', () => {
    // 1. Cursor rule
    const cursorRulesDir = path.join(tempBaseDir, '.cursor', 'rules');
    fs.mkdirSync(cursorRulesDir, { recursive: true });
    fs.writeFileSync(path.join(cursorRulesDir, 'security.mdc'), 'Rule content');

    // 2. Copilot instruction
    const copilotDir = path.join(tempBaseDir, '.github');
    fs.mkdirSync(copilotDir, { recursive: true });
    fs.writeFileSync(path.join(copilotDir, 'copilot-instructions.md'), '# Copilot guidelines');

    // 3. Agent skill
    const skillDir = path.join(tempBaseDir, '.agents', 'skills', 'test-skill');
    fs.mkdirSync(skillDir, { recursive: true });
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), '---\nname: test-skill\ndescription: Test agent skill\n---\n');

    const scanner = new AgentEcosystemScanner({
      baseDir: tempBaseDir,
      homeDir: tempHomeDir,
    });

    const report = scanner.scan();
    expect(report.totalSkillsFound).toBe(3);

    const cursorEnv = report.environments.find(e => e.platform === 'cursor');
    expect(cursorEnv?.skills.some(s => s.name === 'security')).toBe(true);

    const copilotEnv = report.environments.find(e => e.platform === 'vscode-copilot');
    expect(copilotEnv?.exists).toBe(true);
    expect(copilotEnv?.skills.length).toBe(1);

    const skillsEnv = report.environments.find(e => e.platform === 'skills-plugins');
    expect(skillsEnv?.skills.some(s => s.name === 'test-skill')).toBe(true);
  });

  it('scans across multiple client formats without crashing', () => {
    const scanner = new AgentEcosystemScanner({
      baseDir: tempBaseDir,
      homeDir: tempHomeDir,
    });

    const report = scanner.scan();
    expect(report.environments.length).toBe(11);
    expect(typeof report.overallPostureScore).toBe('number');
    expect(report.overallPostureScore).toBeGreaterThanOrEqual(0);
    expect(report.overallPostureScore).toBeLessThanOrEqual(100);
  });
});
