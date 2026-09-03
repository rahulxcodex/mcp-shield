import { MCPProtocolStateMachine, MCPProtocolState } from '../../src/core/mcp-protocol-state-machine';
import { AttackCorpusRegistry } from '../../src/security/attack-corpus';
import { SecurityIntelligenceEngine } from '../../src/security/intelligence-engine';
import { ServerIdentityVerifier } from '../../src/security/server-identity';
import { AIRuntimeSecurityPlatform } from '../../src/core/ai-runtime-security';
import { MCPSecurityBenchmarkRunner } from '../../benchmarks/mcp-security-benchmark';

describe('Step 1-10 Moat & Security Invariants Verification', () => {
  describe('Step 1: MCP Protocol State Machine', () => {
    it('should initialize in CONNECTING state and transition only on valid initialize', () => {
      const sm = new MCPProtocolStateMachine();
      expect(sm.getState()).toBe(MCPProtocolState.CONNECTING);

      // Premature tool call
      const premature = sm.evaluateClientMessage({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'list_files' },
      });
      expect(premature.valid).toBe(false);
      expect(premature.errorCode).toBe(-32002);

      // Valid initialize
      const init = sm.evaluateClientMessage({
        jsonrpc: '2.0',
        id: 10,
        method: 'initialize',
        params: { capabilities: {} },
      });
      expect(init.valid).toBe(true);
      expect(sm.getState()).toBe(MCPProtocolState.WAITING_FOR_INITIALIZE_RESPONSE);

      // Server response completes init
      const serverResp = sm.evaluateServerMessage({
        jsonrpc: '2.0',
        id: 10,
        result: { capabilities: { tools: {} } },
      });
      expect(serverResp.valid).toBe(true);
      expect(sm.getState()).toBe(MCPProtocolState.READY);
    });

    it('should reject client cancellation of initialize request', () => {
      const sm = new MCPProtocolStateMachine();
      sm.evaluateClientMessage({ jsonrpc: '2.0', id: 10, method: 'initialize', params: {} });
      const cancel = sm.evaluateClientMessage({
        jsonrpc: '2.0',
        method: 'notifications/cancelled',
        params: { requestId: 10 },
      });
      expect(cancel.valid).toBe(false);
    });

    it('should enforce fail-closed framing and block handshake replay in READY state', () => {
      const sm = new MCPProtocolStateMachine();
      // Fail-closed framing: invalid JSON-RPC version
      const malformed = sm.evaluateClientMessage({ jsonrpc: '1.0', id: 1, method: 'ping' });
      expect(malformed.valid).toBe(false);
      expect(malformed.errorCode).toBe(-32600);

      // Handshake to READY
      sm.evaluateClientMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
      sm.evaluateServerMessage({ jsonrpc: '2.0', id: 1, result: { capabilities: {} } });
      expect(sm.getState()).toBe(MCPProtocolState.READY);

      // Handshake replay rejection
      const replay = sm.evaluateClientMessage({ jsonrpc: '2.0', id: 2, method: 'initialize', params: {} });
      expect(replay.valid).toBe(false);
      expect(replay.errorCode).toBe(-32600);
      expect(replay.errorMessage).toContain('Handshake replay');
    });
  });

  describe('Step 2: Proprietary Attack Corpus', () => {
    it('should provide structured attacks across 7 categories with complete reasoning chains', () => {
      const attacks = AttackCorpusRegistry.getAllAttacks();
      expect(attacks.length).toBeGreaterThanOrEqual(13);

      // Verify expanded corpus entries
      expect(AttackCorpusRegistry.getAttackById('ATK-PROMPT-003')).toBeDefined();
      expect(AttackCorpusRegistry.getAttackById('ATK-ABUSE-002')).toBeDefined();
      expect(AttackCorpusRegistry.getAttackById('ATK-ABUSE-003')).toBeDefined();

      const stats = AttackCorpusRegistry.getStatistics();
      expect(stats.byCategory.protocol).toBeGreaterThan(0);
      expect(stats.byCategory.prompt_injection).toBeGreaterThan(0);
      expect(stats.byCategory.shell).toBeGreaterThan(0);
      expect(stats.byCategory.filesystem).toBeGreaterThan(0);
      expect(stats.byCategory.network).toBeGreaterThan(0);
      expect(stats.byCategory.credential).toBeGreaterThan(0);
      expect(stats.byCategory.agent_abuse).toBeGreaterThan(0);

      for (const atk of attacks) {
        expect(atk.reasoning_chain.parserRepresentation).toBeDefined();
        expect(atk.reasoning_chain.policyDecision).toBeDefined();
        expect(atk.reasoning_chain.patch).toBeDefined();
        expect(atk.reasoning_chain.regressionTest).toBeDefined();
      }
    });
  });

  describe('Step 3: Security Intelligence & Risk Engine', () => {
    it('should calculate deterministic risk scores with transparent factor breakdown', () => {
      const risk = SecurityIntelligenceEngine.calculateRiskScore({
        serverId: 'test-srv',
        toolName: 'http_request',
        actionType: 'egress',
        destinationHost: 'http://169.254.169.254/latest/meta-data',
        payloadSnippet: 'AKIAIOSFODNN7EXAMPLE',
      });

      expect(risk.compositeScore).toBeGreaterThanOrEqual(70);
      expect(risk.factors.destinationRisk).toBeGreaterThan(0);
      expect(risk.factors.credentialExposure).toBeGreaterThan(0);
      expect(risk.rationale.length).toBeGreaterThan(0);
    });

    it('should detect stateful n-gram sequence anomalies and apply non-linear risk compounding', () => {
      // Test stateful n-gram anomaly detection
      const nGram = SecurityIntelligenceEngine.evaluateNGramAnomaly(['read_file'], 'http_request');
      expect(nGram.anomalyScore).toBeGreaterThan(0);
      expect(nGram.rationale[0]).toContain('Exfiltration');

      // Test non-linear compounding across multi-vector threats
      const singleVectorScore = SecurityIntelligenceEngine.calculateNonLinearScore({
        capabilityRisk: 25,
        behaviorAnomaly: 0,
        provenanceRisk: 0,
        destinationRisk: 0,
        credentialExposure: 0,
        policyViolations: 0,
        historicalReputation: 0,
      });
      expect(singleVectorScore).toBe(25);

      const multiVectorScore = SecurityIntelligenceEngine.calculateNonLinearScore({
        capabilityRisk: 25,
        behaviorAnomaly: 0,
        provenanceRisk: 0,
        destinationRisk: 30,
        credentialExposure: 30,
        policyViolations: 0,
        historicalReputation: 0,
      });
      // 85 raw * (1 + 2 * 0.12) = 105.4 -> capped at 100
      expect(multiVectorScore).toBe(100);
    });

    it('should simulate policy enforcement and recommend alternative outcomes', () => {
      const sim = SecurityIntelligenceEngine.simulateExecution({
        serverId: 'sim-srv',
        toolName: 'exec_cmd',
        args: { url: 'http://169.254.169.254' },
      });
      expect(sim.simulatedAction).toBe('BLOCK');
      expect(sim.triggeredRules.length).toBeGreaterThan(0);
    });
  });

  describe('Step 4: Standardized Security Benchmark', () => {
    it('should execute benchmark across all categories and yield an enterprise score >= 80', async () => {
      const report = await MCPSecurityBenchmarkRunner.runBenchmark();
      expect(report.overallScore).toBeGreaterThanOrEqual(80);
      expect(report.summary.detectionRatePct).toBeGreaterThanOrEqual(85);
      expect(report.summary.averageP50Us).toBeGreaterThan(0);
      expect(report.summary.systemRating).toMatch(/^(A\+|A)$/);
    });
  });

  describe('Step 5: Server Identity & Provenance Drift', () => {
    it('should detect binary replacement, schema drift, and unauthorized tools', () => {
      const verifier = new ServerIdentityVerifier();
      const baseline = {
        serverId: 'fs-srv',
        executableHash: 'hash-v1',
        schemaHash: 'schema-v1',
        toolInventory: ['read_file', 'write_file'],
        version: '1.0.0',
        command: 'node',
        args: [],
        declaredCapabilities: [],
        isSigned: true,
        provenanceSignature: 'sig-base',
      };

      const tampered = {
        ...baseline,
        executableHash: 'hash-v2-modified',
        toolInventory: ['read_file', 'write_file', 'unauthorized_exec'],
      };

      const drift = verifier.detectDrift(baseline, tampered);
      expect(drift.hasDrift).toBe(true);
      expect(drift.driftTypes).toContain('BINARY_REPLACED');
      expect(drift.driftTypes).toContain('CAPABILITY_EXPANDED');
    });
  });

  describe('Step 10: AI Runtime Security Platform', () => {
    it('should enforce guardrails across Coding, Browser, and Multi-Agent runtimes', () => {
      // 1. Coding Agent destructive command block
      AIRuntimeSecurityPlatform.registerAgentSession({
        agentId: 'coder-01',
        agentType: 'coding_agent',
        sessionId: 'sess-code-test',
        delegationDepth: 1,
        maxAllowedDepth: 5,
        principalUser: 'alice',
        organizationId: 'org-1',
      });
      const codeDec = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: 'sess-code-test',
        toolName: 'exec_terminal',
        intent: {
          actionCategory: 'EXECUTE',
          intentDescription: 'Run destructive command',
          targetResource: 'bash',
          payload: 'rm -rf /',
        },
      });
      expect(codeDec.allowed).toBe(false);
      expect(codeDec.action).toBe('BLOCK');

      // 2. Browser Agent SSRF navigation block
      AIRuntimeSecurityPlatform.registerAgentSession({
        agentId: 'browser-01',
        agentType: 'browser_agent',
        sessionId: 'sess-browser-test',
        delegationDepth: 1,
        maxAllowedDepth: 5,
        principalUser: 'bob',
        organizationId: 'org-1',
      });
      const browserDec = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: 'sess-browser-test',
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Visit cloud metadata endpoint',
          targetResource: 'http://169.254.169.254/latest/meta-data',
          payload: {},
        },
      });
      expect(browserDec.allowed).toBe(false);
      expect(browserDec.action).toBe('BLOCK');

      // 3. Multi-Agent Runaway Loop termination
      AIRuntimeSecurityPlatform.registerAgentSession({
        agentId: 'agent-swarm',
        agentType: 'multi_agent',
        sessionId: 'sess-multi-test',
        delegationDepth: 8,
        maxAllowedDepth: 5,
        principalUser: 'charlie',
        organizationId: 'org-1',
      });
      const multiDec = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: 'sess-multi-test',
        toolName: 'delegate_subtask',
        intent: {
          actionCategory: 'DELEGATE',
          intentDescription: 'Recursive subagent loop',
          targetResource: 'subagent-9',
          payload: {},
        },
      });
      expect(multiDec.allowed).toBe(false);
      expect(multiDec.action).toBe('BLOCK');
      expect(multiDec.violatedPolicies[0]).toContain('Multi-Agent Runaway Delegation Loop');
    });
  });
});
