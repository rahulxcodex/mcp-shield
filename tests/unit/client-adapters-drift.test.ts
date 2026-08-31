import * as fs from 'fs';
import * as path from 'path';
import { ProtectCommand } from '../../src/cli/commands/protect';

describe('MCP Client Config Adapters & Version Drift Verification', () => {
  const fixturesDir = path.join(__dirname, '..', 'fixtures', 'client-configs');

  it('should reliably protect Claude Desktop v1 config while preserving env and args', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'claude_desktop_config.v1.json'), 'utf8');
    const res = ProtectCommand.patchConfigString(raw, 'Claude Desktop', '/bin/mcp-shield');

    expect(res.errors).toHaveLength(0);
    expect(res.patched).toBe(true);
    expect(res.serverCount).toBe(2);

    const parsed = JSON.parse(res.content);
    expect(parsed.mcpServers.filesystem.args).toEqual([
      '/bin/mcp-shield', 'wrap', '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', '/Users/developer/workspace'
    ]);
    expect(parsed.mcpServers.filesystem.env.NODE_ENV).toBe('production');
    expect(parsed.mcpServers.github.args).toEqual([
      '/bin/mcp-shield', 'wrap', '--', 'docker', 'run', '-i', '--rm', 'mcp/github'
    ]);
    expect(parsed.mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN).toBe('ghp_mocktoken1234567890');
  });

  it('should reliably protect Cursor MCP v1 config while preserving disabled status', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'cursor_mcp.v1.json'), 'utf8');
    const res = ProtectCommand.patchConfigString(raw, 'Cursor IDE', '/bin/mcp-shield');

    expect(res.errors).toHaveLength(0);
    expect(res.patched).toBe(true);
    expect(res.serverCount).toBe(2);

    const parsed = JSON.parse(res.content);
    expect(parsed.mcpServers['local-python'].disabled).toBe(false);
    expect(parsed.mcpServers['fetch-tool'].disabled).toBe(true);
    expect(parsed.mcpServers['fetch-tool'].args).toEqual([
      '/bin/mcp-shield', 'wrap', '--', 'uvx', 'mcp-server-fetch'
    ]);
  });

  it('should reliably protect Windsurf MCP config', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'windsurf_mcp_config.v1.json'), 'utf8');
    const res = ProtectCommand.patchConfigString(raw, 'Windsurf', '/bin/mcp-shield');

    expect(res.errors).toHaveLength(0);
    expect(res.patched).toBe(true);
    expect(res.serverCount).toBe(1);

    const parsed = JSON.parse(res.content);
    expect(parsed.mcpServers['terminal-agent'].env.DEBUG).toBe('mcp:*');
    expect(parsed.mcpServers['terminal-agent'].args).toEqual([
      '/bin/mcp-shield', 'wrap', '--', 'node', '/opt/mcp/terminal/index.js'
    ]);
  });

  it('should reliably protect Cline MCP settings while preserving autoApprove array', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'cline_mcp_settings.v1.json'), 'utf8');
    const res = ProtectCommand.patchConfigString(raw, 'Cline', '/bin/mcp-shield');

    expect(res.errors).toHaveLength(0);
    expect(res.patched).toBe(true);
    expect(res.serverCount).toBe(1);

    const parsed = JSON.parse(res.content);
    expect(parsed.mcpServers.sqlite.autoApprove).toEqual(['read_query']);
    expect(parsed.mcpServers.sqlite.args).toEqual([
      '/bin/mcp-shield', 'wrap', '--', 'uvx', 'mcp-server-sqlite', '--db-path', '~/test.db'
    ]);
  });

  it('should be strictly idempotent and never double-wrap already protected configs', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'claude_desktop_config.v1.json'), 'utf8');
    const firstPass = ProtectCommand.patchConfigString(raw, 'Claude Desktop', '/bin/mcp-shield');
    expect(firstPass.patched).toBe(true);

    const secondPass = ProtectCommand.patchConfigString(firstPass.content, 'Claude Desktop', '/bin/mcp-shield');
    expect(secondPass.patched).toBe(false);
    expect(secondPass.alreadyProtectedCount).toBe(2);
    expect(secondPass.content).toBe(firstPass.content);
  });

  it('should gracefully detect and reject breaking schema drift without corrupting files', () => {
    const raw = fs.readFileSync(path.join(fixturesDir, 'breaking_schema.json'), 'utf8');
    const res = ProtectCommand.patchConfigString(raw, 'Unknown Client', '/bin/mcp-shield');

    expect(res.patched).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
    expect(res.errors[0]).toContain('Field "mcpServers" must be a key-value object map');
  });

  it('should return error on malformed JSON payload', () => {
    const malformed = '{ "mcpServers": { "bad": { command: "unquoted" } } }';
    const res = ProtectCommand.patchConfigString(malformed, 'Broken Client');

    expect(res.patched).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
    expect(res.errors[0]).toContain('JSON Syntax Error');
  });
});
