import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export type AgentPlatform =
  | 'claude'
  | 'cursor'
  | 'windsurf'
  | 'gemini-cli'
  | 'vscode-cline'
  | 'vscode-roo'
  | 'vscode-copilot'
  | 'codex'
  | 'amazon-q'
  | 'local-mcp'
  | 'skills-plugins';

export interface DiscoveredMcpServer {
  id: string;
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  disabled: boolean;
  autoApprove: string[];
  isProtected: boolean;
  riskFindings: string[];
}

export interface DiscoveredSkillPlugin {
  name: string;
  path: string;
  type: 'skill' | 'cursor-rule' | 'windsurf-rule' | 'copilot-instruction';
  description?: string;
  contentSnippet?: string;
}

export interface DiscoveredAgentEnvironment {
  platform: AgentPlatform;
  displayName: string;
  configPath: string;
  exists: boolean;
  servers: DiscoveredMcpServer[];
  skills: DiscoveredSkillPlugin[];
  riskFindings: string[];
}

export interface EcosystemDiscoveryReport {
  timestamp: number;
  totalAgentsFound: number;
  totalServersFound: number;
  totalSkillsFound: number;
  protectedServersCount: number;
  unprotectedServersCount: number;
  environments: DiscoveredAgentEnvironment[];
  globalRisks: {
    exposedSecrets: string[];
    autoApproveExploits: string[];
    unconstrainedExecution: string[];
  };
  overallPostureScore: number; // 0 to 100
}

export class AgentEcosystemScanner {
  private baseDir: string;
  private homeDir: string;

  constructor(options: { baseDir?: string; homeDir?: string } = {}) {
    this.baseDir = options.baseDir || process.cwd();
    this.homeDir = options.homeDir || os.homedir();
  }

  /**
   * Performs broad discovery across all known agent ecosystems, local configs, and skill plugins.
   */
  public scan(): EcosystemDiscoveryReport {
    const environments: DiscoveredAgentEnvironment[] = [
      this.scanClaude(),
      this.scanCursor(),
      this.scanWindsurf(),
      this.scanGeminiCli(),
      this.scanVsCodeCline(),
      this.scanVsCodeRoo(),
      this.scanVsCodeCopilot(),
      this.scanCodex(),
      this.scanAmazonQ(),
      this.scanLocalMcpConfigs(),
      this.scanSkillsAndPlugins(),
    ];

    let totalServers = 0;
    let totalSkills = 0;
    let protectedCount = 0;
    let activeAgents = 0;

    const exposedSecrets: string[] = [];
    const autoApproveExploits: string[] = [];
    const unconstrainedExecution: string[] = [];

    for (const env of environments) {
      if (env.exists) {
        activeAgents++;
      }
      totalSkills += env.skills.length;

      for (const server of env.servers) {
        totalServers++;
        if (server.isProtected) {
          protectedCount++;
        } else {
          // Check server risks
          for (const [key, val] of Object.entries(server.env || {})) {
            if (/SECRET|KEY|TOKEN|PASSWORD|AUTH|CREDENTIAL/i.test(key) && val) {
              exposedSecrets.push(`${env.displayName} -> ${server.name} env: ${key}`);
            }
          }
          if (server.autoApprove && server.autoApprove.length > 0) {
            autoApproveExploits.push(
              `${env.displayName} -> ${server.name} auto-approves: [${server.autoApprove.join(', ')}]`
            );
          }
          if (/bash|sh|cmd|powershell|pwsh|python|node|eval/i.test(server.command)) {
            unconstrainedExecution.push(
              `${env.displayName} -> ${server.name} runs unconstrained shell: ${server.command}`
            );
          }
        }
      }
    }

    const unprotectedCount = totalServers - protectedCount;

    // Calculate dynamic security posture score (0 - 100)
    let postureScore = 100;
    if (totalServers > 0) {
      const protectionRatio = protectedCount / totalServers;
      postureScore = Math.round(protectionRatio * 50); // 50 pts for protection coverage
    } else {
      postureScore = 75; // Baseline if no MCP servers configured
    }

    // Penalties for dangerous misconfigurations
    postureScore -= Math.min(25, exposedSecrets.length * 5);
    postureScore -= Math.min(15, autoApproveExploits.length * 5);
    postureScore -= Math.min(15, unconstrainedExecution.length * 3);
    postureScore = Math.max(10, Math.min(100, postureScore));

    return {
      timestamp: Date.now(),
      totalAgentsFound: activeAgents,
      totalServersFound: totalServers,
      totalSkillsFound: totalSkills,
      protectedServersCount: protectedCount,
      unprotectedServersCount: unprotectedCount,
      environments,
      globalRisks: {
        exposedSecrets,
        autoApproveExploits,
        unconstrainedExecution,
      },
      overallPostureScore: postureScore,
    };
  }

  // 1. Claude Desktop
  public scanClaude(): DiscoveredAgentEnvironment {
    let configPath = path.join(this.homeDir, '.config', 'Claude', 'claude_desktop_config.json');
    if (process.platform === 'win32') {
      configPath = path.join(this.homeDir, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
    } else if (process.platform === 'darwin') {
      configPath = path.join(this.homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    }
    return this.parseStandardMcpConfig('claude', 'Claude Desktop', configPath);
  }

  // 2. Cursor IDE
  public scanCursor(): DiscoveredAgentEnvironment {
    const globalConfig = path.join(this.homeDir, '.cursor', 'mcp.json');
    const localConfig = path.join(this.baseDir, '.cursor', 'mcp.json');
    const targetPath = fs.existsSync(localConfig) ? localConfig : globalConfig;
    const env = this.parseStandardMcpConfig('cursor', 'Cursor IDE', targetPath);

    // Look for .cursor/rules
    const rulesDir = path.join(this.baseDir, '.cursor', 'rules');
    if (fs.existsSync(rulesDir)) {
      try {
        const files = fs.readdirSync(rulesDir);
        for (const file of files) {
          if (file.endsWith('.mdc') || file.endsWith('.md')) {
            const rulePath = path.join(rulesDir, file);
            env.skills.push({
              name: file.replace(/\.(mdc|md)$/, ''),
              path: rulePath,
              type: 'cursor-rule',
              description: `Cursor IDE system rule: ${file}`,
            });
          }
        }
      } catch {}
    }
    return env;
  }

  // 3. Windsurf
  public scanWindsurf(): DiscoveredAgentEnvironment {
    const globalConfig = path.join(this.homeDir, '.codeium', 'windsurf', 'mcp_config.json');
    const localConfig = path.join(this.baseDir, '.windsurf', 'mcp_config.json');
    const targetPath = fs.existsSync(localConfig) ? localConfig : globalConfig;
    const env = this.parseStandardMcpConfig('windsurf', 'Windsurf', targetPath);

    // Look for .windsurf/rules
    const rulesDir = path.join(this.baseDir, '.windsurf', 'rules');
    if (fs.existsSync(rulesDir)) {
      try {
        const files = fs.readdirSync(rulesDir);
        for (const file of files) {
          if (file.endsWith('.md')) {
            const rulePath = path.join(rulesDir, file);
            env.skills.push({
              name: file.replace(/\.md$/, ''),
              path: rulePath,
              type: 'windsurf-rule',
              description: `Windsurf cascade rule: ${file}`,
            });
          }
        }
      } catch {}
    }
    return env;
  }

  // 4. Gemini CLI & Antigravity
  public scanGeminiCli(): DiscoveredAgentEnvironment {
    const geminiSettings = path.join(this.homeDir, '.gemini', 'settings.json');
    const antigravityMcp = path.join(this.homeDir, '.gemini', 'antigravity', 'mcp');
    const exists = fs.existsSync(geminiSettings) || fs.existsSync(antigravityMcp);

    const servers: DiscoveredMcpServer[] = [];
    const skills: DiscoveredSkillPlugin[] = [];
    const riskFindings: string[] = [];

    if (fs.existsSync(geminiSettings)) {
      try {
        const raw = fs.readFileSync(geminiSettings, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed.mcpServers) {
          servers.push(...this.extractServers(parsed.mcpServers));
        }
      } catch (err: any) {
        riskFindings.push(`Error parsing Gemini settings: ${err.message}`);
      }
    }

    if (fs.existsSync(antigravityMcp)) {
      try {
        const entries = fs.readdirSync(antigravityMcp, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            servers.push({
              id: `gemini-${entry.name}`,
              name: entry.name,
              command: 'antigravity-mcp-sidecar',
              args: [entry.name],
              env: {},
              disabled: false,
              autoApprove: [],
              isProtected: true,
              riskFindings: [],
            });
          }
        }
      } catch {}
    }

    return {
      platform: 'gemini-cli',
      displayName: 'Gemini CLI / Antigravity',
      configPath: fs.existsSync(geminiSettings) ? geminiSettings : antigravityMcp,
      exists,
      servers,
      skills,
      riskFindings,
    };
  }

  // 5. VS Code Cline
  public scanVsCodeCline(): DiscoveredAgentEnvironment {
    let configPath = path.join(
      this.homeDir,
      '.config',
      'Code',
      'User',
      'globalStorage',
      'saoudrizwan.claude-dev',
      'settings',
      'cline_mcp_settings.json'
    );
    if (process.platform === 'win32') {
      configPath = path.join(
        this.homeDir,
        'AppData',
        'Roaming',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
    } else if (process.platform === 'darwin') {
      configPath = path.join(
        this.homeDir,
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
    }
    return this.parseStandardMcpConfig('vscode-cline', 'Cline (VS Code)', configPath);
  }

  // 6. VS Code Roo Code
  public scanVsCodeRoo(): DiscoveredAgentEnvironment {
    let configPath = path.join(
      this.homeDir,
      '.config',
      'Code',
      'User',
      'globalStorage',
      'rooveterinaryinc.roo-cline',
      'settings',
      'cline_mcp_settings.json'
    );
    if (process.platform === 'win32') {
      configPath = path.join(
        this.homeDir,
        'AppData',
        'Roaming',
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline',
        'settings',
        'cline_mcp_settings.json'
      );
    } else if (process.platform === 'darwin') {
      configPath = path.join(
        this.homeDir,
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline',
        'settings',
        'cline_mcp_settings.json'
      );
    }
    return this.parseStandardMcpConfig('vscode-roo', 'Roo Code (VS Code)', configPath);
  }

  // 7. GitHub Copilot & VS Code Native
  public scanVsCodeCopilot(): DiscoveredAgentEnvironment {
    const copilotInstructions = path.join(this.baseDir, '.github', 'copilot-instructions.md');
    const exists = fs.existsSync(copilotInstructions);
    const skills: DiscoveredSkillPlugin[] = [];

    if (exists) {
      skills.push({
        name: 'copilot-instructions',
        path: copilotInstructions,
        type: 'copilot-instruction',
        description: 'Repository-level GitHub Copilot instructions',
      });
    }

    return {
      platform: 'vscode-copilot',
      displayName: 'GitHub Copilot / VS Code',
      configPath: copilotInstructions,
      exists,
      servers: [],
      skills,
      riskFindings: [],
    };
  }

  // 8. OpenAI Codex / ChatGPT Desktop
  public scanCodex(): DiscoveredAgentEnvironment {
    const codexConfig = path.join(this.homeDir, '.codex', 'config.json');
    const openaiMcp = path.join(this.homeDir, '.openai', 'mcp.json');
    const targetPath = fs.existsSync(codexConfig) ? codexConfig : openaiMcp;
    return this.parseStandardMcpConfig('codex', 'OpenAI Codex / ChatGPT Desktop', targetPath);
  }

  // 9. Amazon Q Developer
  public scanAmazonQ(): DiscoveredAgentEnvironment {
    const qConfig = path.join(this.homeDir, '.aws', 'amazon-q', 'mcp.json');
    return this.parseStandardMcpConfig('amazon-q', 'Amazon Q Developer', qConfig);
  }

  // 10. Local MCP Configs in Workspace
  public scanLocalMcpConfigs(): DiscoveredAgentEnvironment {
    const candidates = [
      path.join(this.baseDir, '.mcp.json'),
      path.join(this.baseDir, 'mcp.json'),
      path.join(this.baseDir, 'mcp-servers.json'),
    ];

    let foundPath = '';
    let parsedServers: DiscoveredMcpServer[] = [];
    const risks: string[] = [];

    for (const c of candidates) {
      if (fs.existsSync(c)) {
        foundPath = c;
        try {
          const raw = fs.readFileSync(c, 'utf8');
          const data = JSON.parse(raw);
          const rawServers = data.mcpServers || data.servers || data;
          if (typeof rawServers === 'object' && !Array.isArray(rawServers)) {
            parsedServers = this.extractServers(rawServers);
          }
        } catch (err: any) {
          risks.push(`Error reading local MCP config ${c}: ${err.message}`);
        }
        break;
      }
    }

    // Also check package.json
    const pkgPath = path.join(this.baseDir, 'package.json');
    if (!foundPath && fs.existsSync(pkgPath)) {
      try {
        const raw = fs.readFileSync(pkgPath, 'utf8');
        const pkg = JSON.parse(raw);
        if (pkg.mcpServers) {
          foundPath = pkgPath;
          parsedServers = this.extractServers(pkg.mcpServers);
        }
      } catch {}
    }

    return {
      platform: 'local-mcp',
      displayName: 'Local Workspace MCP',
      configPath: foundPath || path.join(this.baseDir, '.mcp.json'),
      exists: !!foundPath,
      servers: parsedServers,
      skills: [],
      riskFindings: risks,
    };
  }

  // 11. Skills & Plugins Discovery
  public scanSkillsAndPlugins(): DiscoveredAgentEnvironment {
    const skillsDir = path.join(this.baseDir, '.agents', 'skills');
    const skills: DiscoveredSkillPlugin[] = [];
    const exists = fs.existsSync(skillsDir);

    if (exists) {
      try {
        const skillEntries = fs.readdirSync(skillsDir, { withFileTypes: true });
        for (const entry of skillEntries) {
          if (entry.isDirectory()) {
            const skillMd = path.join(skillsDir, entry.name, 'SKILL.md');
            if (fs.existsSync(skillMd)) {
              let desc = `Custom agent skill: ${entry.name}`;
              try {
                const content = fs.readFileSync(skillMd, 'utf8');
                const descMatch = content.match(/description:\s*([^\r\n]+)/i);
                if (descMatch) desc = descMatch[1].trim();
              } catch {}
              skills.push({
                name: entry.name,
                path: skillMd,
                type: 'skill',
                description: desc,
              });
            }
          }
        }
      } catch {}
    }

    return {
      platform: 'skills-plugins',
      displayName: 'Agent Skills & Custom Plugins',
      configPath: skillsDir,
      exists,
      servers: [],
      skills,
      riskFindings: [],
    };
  }

  private parseStandardMcpConfig(
    platform: AgentPlatform,
    displayName: string,
    configPath: string
  ): DiscoveredAgentEnvironment {
    const exists = fs.existsSync(configPath);
    const servers: DiscoveredMcpServer[] = [];
    const riskFindings: string[] = [];

    if (exists) {
      try {
        const raw = fs.readFileSync(configPath, 'utf8');
        const data = JSON.parse(raw);
        const rawServers = data.mcpServers || data.servers || {};
        servers.push(...this.extractServers(rawServers));
      } catch (err: any) {
        riskFindings.push(`Error parsing ${displayName} config: ${err.message}`);
      }
    }

    return {
      platform,
      displayName,
      configPath,
      exists,
      servers,
      skills: [],
      riskFindings,
    };
  }

  private extractServers(rawServers: Record<string, any>): DiscoveredMcpServer[] {
    const servers: DiscoveredMcpServer[] = [];
    for (const [name, cfg] of Object.entries(rawServers)) {
      if (!cfg || typeof cfg !== 'object') continue;

      const cmd = String(cfg.command || '');
      const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
      const env = (cfg.env && typeof cfg.env === 'object') ? cfg.env : {};
      const disabled = !!cfg.disabled;
      const autoApprove = Array.isArray(cfg.autoApprove) ? cfg.autoApprove.map(String) : [];

      const isProtected =
        cmd.includes('mcp-shield') ||
        cmd.includes('mcpshld') ||
        args.some((a: string) => a.includes('mcp-shield') || a.includes('mcpshld'));

      const serverRisks: string[] = [];
      if (!isProtected) {
        serverRisks.push('Unprotected: Tool calls execute directly without AST firewall or DLP sanitization');
      }
      if (autoApprove.length > 0) {
        serverRisks.push(`Auto-approve enabled for: ${autoApprove.join(', ')}`);
      }

      servers.push({
        id: name,
        name,
        command: cmd,
        args,
        env,
        disabled,
        autoApprove,
        isProtected,
        riskFindings: serverRisks,
      });
    }
    return servers;
  }
}
