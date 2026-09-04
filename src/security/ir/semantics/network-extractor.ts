import { SecurityCommandIR, SemanticThreatFinding } from '../ir-types';

export class NetworkSemanticExtractor {
  public static extract(ir: SecurityCommandIR): SemanticThreatFinding[] {
    const findings: SemanticThreatFinding[] = [];

    for (const action of ir.actions) {
      if (action.type === 'NETWORK_REQUEST') {
        const dest = action.destination.toLowerCase();
        const isUntrusted = !dest.includes('github.com') && !dest.includes('npm.org');

        if (isUntrusted) {
          findings.push({
            ruleId: 'NET-UNTRUSTED-EGRESS',
            category: 'NETWORK',
            severity: 0.85,
            explanation: `Command initiates outbound network communication to external target: "${action.destination}"`,
            action
          });
        }
      }
    }

    return findings;
  }
}
