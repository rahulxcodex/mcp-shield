import { AgentEcosystemScanner, EcosystemDiscoveryReport } from '../../scanner/agent-ecosystem-scanner';

export class ScanCommand {
  public static run(options: { baseDir?: string; homeDir?: string; json?: boolean } = {}) {
    const bold = '\x1b[1m';
    const red = '\x1b[31m';
    const yellow = '\x1b[33m';
    const green = '\x1b[32m';
    const cyan = '\x1b[36m';
    const reset = '\x1b[0m';

    const scanner = new AgentEcosystemScanner({
      baseDir: options.baseDir,
      homeDir: options.homeDir,
    });
    const report: EcosystemDiscoveryReport = scanner.scan();

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      return report;
    }

    console.log(`\n${bold}🛡️  MCP SHIELD — Agent Ecosystem & Security Audit${reset}`);
    console.log('──────────────────────────────────────────────────');

    console.log(`${cyan}Active Agent Platforms:${reset} ${report.totalAgentsFound}`);
    for (const env of report.environments) {
      if (env.exists) {
        const count = env.servers.length;
        const skillsCount = env.skills.length;
        let details = `${count} server(s)`;
        if (skillsCount > 0) details += `, ${skillsCount} skill(s)`;
        console.log(`  • ${bold}${env.displayName}${reset}: ${details}`);
      }
    }

    console.log(`\n${cyan}MCP Servers Summary:${reset}`);
    console.log(`  Total Servers:      ${report.totalServersFound}`);
    console.log(`  ${green}Protected Servers:${reset}  ${report.protectedServersCount}`);
    console.log(`  ${red}Unprotected:${reset}        ${report.unprotectedServersCount}`);
    console.log(`  Skills / Plugins:   ${report.totalSkillsFound}`);

    const criticalCount = report.globalRisks.exposedSecrets.length;
    const highCount = report.globalRisks.autoApproveExploits.length;
    const mediumCount = report.globalRisks.unconstrainedExecution.length;

    console.log(`\n${cyan}Threat Indicators:${reset}`);
    if (criticalCount > 0) {
      console.log(`  ${red}${bold}CRITICAL${reset} Exposed Secrets:    ${criticalCount}`);
      for (const s of report.globalRisks.exposedSecrets.slice(0, 3)) {
        console.log(`    - ${s}`);
      }
      if (criticalCount > 3) console.log(`    ... and ${criticalCount - 3} more`);
    }
    if (highCount > 0) {
      console.log(`  ${yellow}${bold}HIGH${reset}     Auto-Approve Flags: ${highCount}`);
      for (const a of report.globalRisks.autoApproveExploits.slice(0, 3)) {
        console.log(`    - ${a}`);
      }
    }
    if (mediumCount > 0) {
      console.log(`  ${cyan}${bold}MEDIUM${reset}   Shell Binaries:     ${mediumCount}`);
    }

    const scoreColor = report.overallPostureScore >= 80 ? green : report.overallPostureScore >= 50 ? yellow : red;
    console.log(`\nSecurity Posture Score: ${scoreColor}${bold}${report.overallPostureScore}/100${reset}`);

    if (report.unprotectedServersCount > 0) {
      console.log(`\nRun ${bold}mcp-shield protect${reset} to secure unprotected servers with AST firewalls and DLP.`);
    } else {
      console.log(`\n${green}✓ All discovered MCP servers are guarded by MCP-Shield.${reset}`);
    }

    return report;
  }
}
