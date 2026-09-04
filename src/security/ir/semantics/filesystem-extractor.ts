import { SecurityCommandIR, SemanticThreatFinding } from '../ir-types';

export class FilesystemSemanticExtractor {
  public static extract(ir: SecurityCommandIR): SemanticThreatFinding[] {
    const findings: SemanticThreatFinding[] = [];

    for (const action of ir.actions) {
      if (action.type === 'DELETE_FILE') {
        if (action.rootOrSystem) {
          findings.push({
            ruleId: 'FS-DESTRUCTIVE-ROOT-DELETE',
            category: 'FILESYSTEM',
            severity: 0.95,
            explanation: `Destructive root deletion targeting system path: "${action.path}"`,
            action
          });
        }
      } else if (action.type === 'READ_FILE') {
        if (action.sensitive) {
          findings.push({
            ruleId: 'FS-SENSITIVE-FILE-READ',
            category: 'FILESYSTEM',
            severity: 0.85,
            explanation: `Attempted access to sensitive system/credential file: "${action.path}"`,
            action
          });
        }
      }
    }

    return findings;
  }
}
