import { SecurityCommandIR, SemanticThreatFinding } from '../ir-types';

export class ProcessSemanticExtractor {
  public static extract(ir: SecurityCommandIR): SemanticThreatFinding[] {
    const findings: SemanticThreatFinding[] = [];

    for (const action of ir.actions) {
      if (action.type === 'PRIVILEGE_ESCALATION') {
        findings.push({
          ruleId: 'PROC-PRIVILEGE-ESCALATION',
          category: 'PROCESS',
          severity: 0.90,
          explanation: `Privilege escalation attempt detected via "${action.method}"`,
          action
        });
      } else if (action.type === 'EXECUTE_PROCESS' && action.elevated) {
        findings.push({
          ruleId: 'PROC-ELEVATED-EXECUTION',
          category: 'PROCESS',
          severity: 0.90,
          explanation: `Dynamic process invocation or elevated execution detected: "${action.binary}"`,
          action
        });
      } else if (action.type === 'ENCODE_DECODE' && action.direction === 'DECODE') {
        findings.push({
          ruleId: 'PROC-OBFUSCATED-DECODE',
          category: 'PROCESS',
          severity: 0.80,
          explanation: `Obfuscated payload decoding pipeline detected (${action.algorithm})`,
          action
        });
      }
    }

    return findings;
  }
}
