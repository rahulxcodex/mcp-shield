export class InstallCommand {
  static run() {
    const bold = '\x1b[1m';
    const green = '\x1b[32m';
    const reset = '\x1b[0m';
    
    console.log(`
${green}${bold}🛡️  MCP-Shield Installed Successfully!${reset}

Your AI Agents are now protected by the Zero-Trust Security Gateway.
We've automatically detected your local configurations and wrapped your servers.

Try running a security scan to see your current risk posture:
  ${bold}mcp-shield scan${reset}
`);
  }
}
