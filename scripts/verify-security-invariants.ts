/**
 * MCP-Shield — Independent Trust & Security Invariants Verification Script
 * Compliant with Step 9 of the IP Value & VRIO Moat Roadmap:
 * - Deterministic reproducible verification for external auditors & red teams
 */

import { MCPProtocolStateMachine, MCPProtocolState } from '../src/core/mcp-protocol-state-machine';
import { AttackCorpusRegistry } from '../src/security/attack-corpus';
import { SecurityIntelligenceEngine } from '../src/security/intelligence-engine';
import { ServerIdentityVerifier } from '../src/security/server-identity';
import { AIRuntimeSecurityPlatform } from '../src/core/ai-runtime-security';

async function main() {
  console.log('======================================================');
  console.log('  MCP-SHIELD FORMAL SECURITY INVARIANTS AUDIT SUITE');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(desc: string, condition: boolean) {
    if (condition) {
      console.log(`  ✅ [PASS] ${desc}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${desc}`);
      failed++;
    }
  }

  // Invariant 1: State machine must not transition to READY before initialize response
  const sm = new MCPProtocolStateMachine();
  assert('Initial protocol state is CONNECTING', sm.getState() === MCPProtocolState.CONNECTING);

  const initMsg = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { capabilities: {} } };
  const evalRes = sm.evaluateClientMessage(initMsg);
  assert('Transition to WAITING_FOR_INITIALIZE_RESPONSE after initialize', sm.getState() === MCPProtocolState.WAITING_FOR_INITIALIZE_RESPONSE);

  const prematureCall = { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file' } };
  const prematureRes = sm.evaluateClientMessage(prematureCall);
  assert('Fail-closed: tools/call rejected before initialization completes', !prematureRes.valid && prematureRes.errorCode === -32002);

  // Invariant 2: Client must not cancel initialize request
  const cancelInit = { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } };
  const cancelRes = sm.evaluateClientMessage(cancelInit);
  assert('Client attempt to cancel initialize request is blocked', !cancelRes.valid);

  // Invariant 3: Attack corpus reasoning chains are complete
  const attacks = AttackCorpusRegistry.getAllAttacks();
  const allChainsValid = attacks.every((a) => a.reasoning_chain && a.reasoning_chain.patch && a.reasoning_chain.regressionTest);
  assert(`Attack Corpus contains ${attacks.length} verified entries with complete reasoning chains`, allChainsValid && attacks.length >= 10);

  // Invariant 4: SSRF to link-local metadata is blocked deterministically
  const ssrfSim = SecurityIntelligenceEngine.simulateExecution({
    serverId: 'test-server',
    toolName: 'http_request',
    args: { url: 'http://169.254.169.254/latest/meta-data' },
  });
  assert('SSRF to AWS link-local metadata (169.254.169.254) is blocked', ssrfSim.simulatedAction === 'BLOCK');

  // Invariant 5: Cleartext AWS credentials trigger bijective DLP sanitization
  const dlpSim = SecurityIntelligenceEngine.simulateExecution({
    serverId: 'test-server',
    toolName: 'read_config',
    args: { secret: 'AKIAIOSFODNN7EXAMPLE' },
  });
  assert('Cleartext AWS access key triggers SANITIZE action', dlpSim.simulatedAction === 'SANITIZE');

  // Invariant 6: AI Runtime blocks runaway multi-agent delegation loop
  AIRuntimeSecurityPlatform.registerAgentSession({
    agentId: 'sub-agent-9',
    agentType: 'multi_agent',
    sessionId: 'sess-loop-test',
    delegationDepth: 6,
    maxAllowedDepth: 5,
    principalUser: 'test-user',
    organizationId: 'org-test',
  });
  const loopDecision = AIRuntimeSecurityPlatform.evaluateAgentAction({
    sessionId: 'sess-loop-test',
    toolName: 'delegate_task',
    intent: {
      actionCategory: 'DELEGATE',
      intentDescription: 'Recursive subagent invocation',
      targetResource: 'agent-sub-10',
      payload: {},
    },
  });
  assert('Multi-Agent runaway delegation loop terminated at max depth', !loopDecision.allowed && loopDecision.action === 'BLOCK');

  // Invariant 7: Provenance drift detection triggers on binary replacement
  const verifier = new ServerIdentityVerifier();
  const driftReport = verifier.detectDrift(
    {
      serverId: 'srv-1',
      executableHash: 'aaa',
      version: '1.0.0',
      command: 'node',
      args: [],
      schemaHash: 'sss',
      toolInventory: ['toolA'],
      declaredCapabilities: [],
      isSigned: true,
      provenanceSignature: 'sig1',
    },
    {
      serverId: 'srv-1',
      executableHash: 'bbb',
      version: '1.0.0',
      command: 'node',
      args: [],
      schemaHash: 'sss',
      toolInventory: ['toolA'],
      declaredCapabilities: [],
      isSigned: true,
      provenanceSignature: 'sig2',
    }
  );
  assert('Server binary replacement detected by provenance drift detector', driftReport.hasDrift && driftReport.driftTypes.includes('BINARY_REPLACED'));

  console.log('\n------------------------------------------------------');
  console.log(`Audit Summary: ${passed}/${passed + failed} Invariants Verified (${Math.round((passed / (passed + failed)) * 100)}%)`);

  if (failed > 0) {
    console.error('❌ Formal security invariant verification failed.');
    process.exit(1);
  } else {
    console.log('✅ All 7 Core Security Invariants Verified Successfully.');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Audit suite error:', err);
  process.exit(1);
});
