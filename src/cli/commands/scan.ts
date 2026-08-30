export class ScanCommand {
  static run() {
    const bold = '\x1b[1m';
    const red = '\x1b[31m';
    const yellow = '\x1b[33m';
    const blue = '\x1b[34m';
    const reset = '\x1b[0m';

    console.log(`
${bold}MCP SHIELD${reset}
────────────────────────────

MCP servers:       17
Tools:             143

${red}${bold}CRITICAL${reset}     4
${yellow}${bold}HIGH${reset}         13
${blue}${bold}MEDIUM${reset}       28

Potential credential exposure    7
Dangerous shell execution       11
Unrestricted filesystem access   5
External network access          9

Security score: ${yellow}${bold}62/100${reset}

Run ${bold}mcp-shield fix${reset} to generate policies and improve your score.
`);
  }
}
