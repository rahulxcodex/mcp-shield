import { SecurityCommandIR, SemanticThreatFinding } from '../ir-types';

export class NetworkSemanticExtractor {
  public static extract(ir: SecurityCommandIR): SemanticThreatFinding[] {
    const findings: SemanticThreatFinding[] = [];

    for (const action of ir.actions) {
      if (action.type === 'NETWORK_REQUEST') {
        let hostname = action.destination.toLowerCase().trim();
        try {
          if (hostname.includes('://')) {
            hostname = new URL(hostname).hostname.toLowerCase();
          } else {
            hostname = hostname.split(/[:/]/)[0];
          }
        } catch {}

        const isTrustedDomain = (domain: string, trusted: string) => {
          return domain === trusted || domain.endsWith('.' + trusted);
        };

        const isTrusted =
          isTrustedDomain(hostname, 'github.com') ||
          isTrustedDomain(hostname, 'npmjs.org') ||
          isTrustedDomain(hostname, 'npmjs.com');

        if (!isTrusted) {
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
