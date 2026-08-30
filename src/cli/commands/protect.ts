import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export class ProtectCommand {
  public static run() {
    console.log('🛡️  MCP-Shield Auto-Discovery & Protection');
    this.patchConfig(this.getClaudeConfigPath(), 'Claude Desktop');
    this.patchConfig(this.getCursorConfigPath(), 'Cursor IDE');
    this.patchConfig(this.getClineConfigPath(), 'Cline (VS Code)');
    this.patchConfig(this.getWindsurfConfigPath(), 'Windsurf');
  }

  private static getClaudeConfigPath() {
    if (process.platform === 'win32') return path.join(os.homedir(), 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
    if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    return '';
  }

  private static getCursorConfigPath() {
    return path.join(os.homedir(), '.cursor', 'mcp.json');
  }

  private static getClineConfigPath() {
    if (process.platform === 'win32') return path.join(os.homedir(), 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
    if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
    return '';
  }
  
  private static getWindsurfConfigPath() {
    return path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json');
  }

  private static patchConfig(configPath: string, name: string) {
    if (!configPath || !fs.existsSync(configPath)) {
      console.log(`[SKIP] ${name} config not found.`);
      return;
    }

    try {
      const backupPath = `${configPath}.backup-${Date.now()}`;
      fs.copyFileSync(configPath, backupPath);
      
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      let patched = false;

      if (config.mcpServers) {
        for (const [serverName, serverDetails] of Object.entries<any>(config.mcpServers)) {
          if (serverDetails.command && !serverDetails.command.includes('mcp-shield')) {
            const originalCmd = serverDetails.command;
            serverDetails.args = ['wrap', '--', originalCmd, ...(serverDetails.args || [])];
            serverDetails.command = 'npx mcp-shield'; 
            patched = true;
          }
        }
      }

      if (patched) {
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        console.log(`[OK] ${name} protected. Backup saved to ${path.basename(backupPath)}.`);
      } else {
        console.log(`[SKIP] ${name} is already protected.`);
      }
    } catch (err: any) {
      console.error(`[ERROR] Failed to patch ${name}: ${err.message}`);
    }
  }
}
