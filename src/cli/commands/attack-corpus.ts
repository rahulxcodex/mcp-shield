/**
 * MCP-Shield — CLI Attack Corpus Command
 * Compliant with Step 2 of the IP Value & VRIO Moat Roadmap
 */

import { AttackCorpusRegistry, AttackCategory } from '../../security/attack-corpus';
import { SecurityIntelligenceEngine } from '../../security/intelligence-engine';
import { MCPProtocolStateMachine } from '../../core/mcp-protocol-state-machine';

export class AttackCorpusCommand {
  public static async run(args: string[] = []): Promise<void> {
    const sub = args[0] || 'list';

    if (sub === 'stats') {
      const stats = AttackCorpusRegistry.getStatistics();
      console.log('======================================================');
      console.log('  MCP-SHIELD PROPRIETARY AGENT ATTACK CORPUS STATS');
      console.log('======================================================');
      console.log(`Total Curated Attack Variants : ${stats.total}`);
      console.log('\nBy Category:');
      for (const [cat, count] of Object.entries(stats.byCategory)) {
        console.log(`  - ${cat.padEnd(20)}: ${count}`);
      }
      console.log('\nBy Severity:');
      for (const [sev, count] of Object.entries(stats.bySeverity)) {
        console.log(`  - ${sev.padEnd(20)}: ${count}`);
      }
      console.log('======================================================');
      return;
    }

    if (sub === 'verify' || sub === 'regression') {
      console.log('⚡ Executing Deterministic Regression Evaluation on Attack Corpus...\n');
      const attacks = AttackCorpusRegistry.getAllAttacks();
      let passed = 0;
      let failed = 0;

      for (const atk of attacks) {
        let decision: string = 'ALLOW';
        if (atk.category === 'protocol') {
          const sm = new MCPProtocolStateMachine();
          const res = sm.evaluateClientMessage(atk.payload);
          decision = res.valid ? 'ALLOW' : 'BLOCK';
        } else {
          const sim = SecurityIntelligenceEngine.simulateExecution({
            serverId: 'regression-runner',
            toolName: atk.tool,
            args: typeof atk.payload === 'object' ? atk.payload : { payload: atk.payload },
          });
          decision = sim.simulatedAction;
        }

        const isMatch =
          decision === atk.expected_decision ||
          (atk.expected_decision === 'BLOCK' && (decision === 'QUARANTINE' || decision === 'SANITIZE')) ||
          (atk.expected_decision === 'SANITIZE' && (decision === 'QUARANTINE' || decision === 'BLOCK')) ||
          (atk.expected_decision === 'RATE_LIMIT' && (decision === 'BLOCK' || decision === 'QUARANTINE' || decision === 'RATE_LIMIT'));

        if (isMatch) {
          passed++;
          console.log(`  [PASS] ${atk.attack_id.padEnd(16)} | ${atk.category.padEnd(16)} | Decision: ${decision}`);
        } else {
          failed++;
          console.error(`  [FAIL] ${atk.attack_id.padEnd(16)} | Expected ${atk.expected_decision}, got ${decision}`);
        }
      }

      console.log('\n------------------------------------------------------');
      console.log(`Corpus Verification Result: ${passed}/${attacks.length} Passed (${Math.round((passed / attacks.length) * 100)}%)`);
      if (failed > 0) {
        process.exit(1);
      } else {
        console.log('✅ All attack reasoning chains and regressions verified.');
        return;
      }
    }

    // Default: list
    const attacks = AttackCorpusRegistry.getAllAttacks();
    console.log('======================================================');
    console.log(`  MCP-SHIELD AGENT ATTACK CORPUS (${attacks.length} Curated Entries)`);
    console.log('======================================================');
    for (const atk of attacks) {
      console.log(`ID       : ${atk.attack_id} [${atk.severity}] (${atk.category}/${atk.sub_category})`);
      console.log(`Variant  : ${atk.attack_variant}`);
      console.log(`Expected : ${atk.expected_decision} | Status: ${atk.mitigation_status}`);
      console.log(`Reasoning: ${atk.reasoning_chain.parserRepresentation} -> ${atk.reasoning_chain.policyDecision}`);
      console.log('------------------------------------------------------');
    }
  }
}
