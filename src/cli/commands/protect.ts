import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface McpServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  disabled?: boolean;
  autoApprove?: string[];
  [key: string]: any;
}

export interface ClientConfigSchema {
  mcpServers?: Record<string, McpServerEntry>;
  [key: string]: any;
}

export interface PatchResult {
  patched: boolean;
  content: string;
  serverCount: number;
  alreadyProtectedCount: number;
  errors: string[];
}

export class ProtectCommand {
  public static run() {
    console.log('🛡️  MCP-Shield Auto-Discovery & Protection');
    this.patchConfigFile(this.getClaudeConfigPath(), 'Claude Desktop');
    this.patchConfigFile(this.getCursorConfigPath(), 'Cursor IDE');
    this.patchConfigFile(this.getClineConfigPath(), 'Cline (VS Code)');
    this.patchConfigFile(this.getWindsurfConfigPath(), 'Windsurf');
  }

  public static getClaudeConfigPath(): string {
    if (process.platform === 'win32') return path.join(os.homedir(), 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
    if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    return path.join(os.homedir(), '.config', 'Claude', 'claude_desktop_config.json');
  }

  public static getCursorConfigPath(): string {
    return path.join(os.homedir(), '.cursor', 'mcp.json');
  }

  public static getClineConfigPath(): string {
    if (process.platform === 'win32') return path.join(os.homedir(), 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
    if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
    return path.join(os.homedir(), '.config', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
  }
  
  public static getWindsurfConfigPath(): string {
    return path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json');
  }

  public static validateConfigSchema(config: any): { isValid: boolean; error?: string } {
    if (!config || typeof config !== 'object') {
      return { isValid: false, error: 'Config root is not a valid JSON object' };
    }

    if (config.mcpServers !== undefined) {
      if (typeof config.mcpServers !== 'object' || config.mcpServers === null || Array.isArray(config.mcpServers)) {
        return { isValid: false, error: 'Field "mcpServers" must be a key-value object map' };
      }

      for (const [serverKey, serverDetails] of Object.entries<any>(config.mcpServers)) {
        if (!serverDetails || typeof serverDetails !== 'object' || Array.isArray(serverDetails)) {
          return { isValid: false, error: `Server "${serverKey}" configuration is not a valid object` };
        }
        if (serverDetails.command !== undefined && typeof serverDetails.command !== 'string') {
          return { isValid: false, error: `Server "${serverKey}.command" must be a string` };
        }
        if (serverDetails.args !== undefined && !Array.isArray(serverDetails.args)) {
          return { isValid: false, error: `Server "${serverKey}.args" must be an array` };
        }
        if (serverDetails.env !== undefined && (typeof serverDetails.env !== 'object' || serverDetails.env === null || Array.isArray(serverDetails.env))) {
          return { isValid: false, error: `Server "${serverKey}.env" must be an object map` };
        }
      }
    }

    return { isValid: true };
  }

  public static patchConfigString(
    rawJson: string,
    clientName: string,
    shieldScriptPath?: string
  ): PatchResult {
    const result: PatchResult = {
      patched: false,
      content: rawJson,
      serverCount: 0,
      alreadyProtectedCount: 0,
      errors: []
    };

    let config: ClientConfigSchema;
    try {
      config = JSON.parse(rawJson);
    } catch (err: any) {
      result.errors.push(`JSON Syntax Error in ${clientName} config: ${err.message}`);
      return result;
    }

    const validation = this.validateConfigSchema(config);
    if (!validation.isValid) {
      result.errors.push(`Schema Validation Failed for ${clientName}: ${validation.error}`);
      return result;
    }

    const shieldScript = shieldScriptPath || (process.argv ? process.argv[1] : 'mcp-shield');

    if (config.mcpServers && Object.keys(config.mcpServers).length > 0) {
      for (const [serverName, serverDetails] of Object.entries<McpServerEntry>(config.mcpServers)) {
        result.serverCount++;

        if (!serverDetails.command) continue;

        // Check if already protected to ensure idempotence
        const isWrapped = (serverDetails.args || []).some(
          arg => typeof arg === 'string' && (arg.includes('mcp-shield') || arg === 'wrap')
        );

        if (isWrapped) {
          result.alreadyProtectedCount++;
          continue;
        }

        const originalCmd = serverDetails.command;
        const originalArgs = serverDetails.args || [];

        serverDetails.args = [shieldScript, 'wrap', '--', originalCmd, ...originalArgs];
        serverDetails.command = process.execPath || 'node';
        result.patched = true;
      }
    }

    if (result.patched) {
      result.content = JSON.stringify(config, null, 2);
    }

    return result;
  }

  public static patchConfigFile(configPath: string, name: string): boolean {
    if (!configPath || !fs.existsSync(configPath)) {
      console.log(`[SKIP] ${name} config not found.`);
      return false;
    }

    try {
      const rawContent = fs.readFileSync(configPath, 'utf8');
      const patchResult = this.patchConfigString(rawContent, name);

      if (patchResult.errors.length > 0) {
        for (const err of patchResult.errors) {
          console.error(`[ERROR] ${err}`);
        }
        return false;
      }

      if (patchResult.patched) {
        const backupPath = `${configPath}.backup-${Date.now()}`;
        fs.copyFileSync(configPath, backupPath);
        fs.writeFileSync(configPath, patchResult.content, 'utf8');
        console.log(`[OK] ${name} protected (${patchResult.serverCount} servers found). Backup saved to ${path.basename(backupPath)}.`);
        return true;
      } else {
        console.log(`[SKIP] ${name} is already protected (${patchResult.alreadyProtectedCount} servers verified).`);
        return false;
      }
    } catch (err: any) {
      console.error(`[ERROR] Failed to patch ${name}: ${err.message}`);
      return false;
    }
  }
}
