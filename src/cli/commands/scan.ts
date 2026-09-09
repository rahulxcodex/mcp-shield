import { AgentEcosystemScanner, EcosystemDiscoveryReport } from '../../scanner/agent-ecosystem-scanner';

export class ScanCommand {
  public static toSarif(report: EcosystemDiscoveryReport): any {
    const rules: any[] = [
      { id: 'MCP-SHIELD-001', name: 'ExposedSecretInConfig', shortDescription: { text: 'Exposed plain text API keys or secrets in MCP configuration.' }, defaultConfiguration: { level: 'error' } },
      { id: 'MCP-SHIELD-002', name: 'AutoApproveExploitFlag', shortDescription: { text: 'Dangerous auto-approval bypass flags detected in MCP server definition.' }, defaultConfiguration: { level: 'warning' } },
      { id: 'MCP-SHIELD-003', name: 'UnconstrainedShellExecution', shortDescription: { text: 'Unsanitized raw shell or interpreter invoked without AST firewall protection.' }, defaultConfiguration: { level: 'note' } }
    ];

    const results: any[] = [];
    for (const secret of report.globalRisks.exposedSecrets) {
      results.push({
        ruleId: 'MCP-SHIELD-001',
        level: 'error',
        message: { text: `Exposed credential identified in MCP configuration: ${secret}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'mcp-config.json' } } }]
      });
    }
    for (const flag of report.globalRisks.autoApproveExploits) {
      results.push({
        ruleId: 'MCP-SHIELD-002',
        level: 'warning',
        message: { text: `Unsafe auto-approval flag detected: ${flag}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'mcp-config.json' } } }]
      });
    }
    for (const shell of report.globalRisks.unconstrainedExecution) {
      results.push({
        ruleId: 'MCP-SHIELD-003',
        level: 'note',
        message: { text: `Unconstrained shell execution surface: ${shell}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'mcp-config.json' } } }]
      });
    }

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'mcp-shield',
            version: '1.0.25',
            informationUri: 'https://github.com/rahulxcodex/mcp-shield',
            rules
          }
        },
        results
      }]
    };
  }

  public static run(options: { baseDir?: string; homeDir?: string; json?: boolean; format?: string; failOn?: 'critical' | 'high' | 'medium' } = {}) {
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

    if (options.format === 'sarif') {
      const sarif = ScanCommand.toSarif(report);
      console.log(JSON.stringify(sarif, null, 2));
      ScanCommand.evaluateFailure(report, options.failOn);
      return sarif;
    }

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      ScanCommand.evaluateFailure(report, options.failOn);
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

    ScanCommand.evaluateFailure(report, options.failOn);
    return report;
  }

  public static evaluateFailure(report: EcosystemDiscoveryReport, failOn?: 'critical' | 'high' | 'medium'): void {
    if (!failOn) return;
    const criticalCount = report.globalRisks.exposedSecrets.length;
    const highCount = report.globalRisks.autoApproveExploits.length;
    const mediumCount = report.globalRisks.unconstrainedExecution.length;

    if (failOn === 'critical' && criticalCount > 0) {
      if (process.env.NODE_ENV !== 'test') process.exit(1);
    } else if (failOn === 'high' && (criticalCount > 0 || highCount > 0)) {
      if (process.env.NODE_ENV !== 'test') process.exit(1);
    } else if (failOn === 'medium' && (criticalCount > 0 || highCount > 0 || mediumCount > 0)) {
      if (process.env.NODE_ENV !== 'test') process.exit(1);
    }
  }
}
