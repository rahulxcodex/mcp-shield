import { ProtocolValidator } from '../../src/core/protocol-validator';
import { CapabilityManifestRegistry, ToolCapabilityManifest } from '../../src/security/capability-manifest';
import { SecuritySession } from '../../src/core/session';
import { CanaryManager } from '../../src/security/canary';
import { COWFileSystem } from '../../src/sandbox/cow-fs';
import { IngressGuard } from '../../src/core/guards/ingress-guard';
import { ToolGuard } from '../../src/core/guards/tool-guard';
import { ExecutionBroker } from '../../src/core/broker/execution-broker';
import { OutputGuard } from '../../src/core/guards/output-guard';
import { LifecycleManager } from '../../src/core/lifecycle/lifecycle-manager';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Capability Execution Broker & Guards Security Suite', () => {
  describe('ProtocolValidator JSON-RPC & Boundary Checks', () => {
    let validator: ProtocolValidator;

    beforeEach(() => {
      validator = new ProtocolValidator({
        maxDepth: 16,
        maxKeys: 50,
        maxOutboundBytes: 1024 * 64 // 64 KB
      });
    });

    it('rejects invalid JSON-RPC envelopes (missing jsonrpc 2.0 or method)', () => {
      const invalidEnvelope = { id: 1, params: {} };
      const res = validator.validateInbound(invalidEnvelope);
      expect(res.valid).toBe(false);
      expect(res.errorCode).toBe(-32600);
      expect(res.errorMessage).toContain('jsonrpc property must be exactly "2.0"');
    });

    it('rejects deep object nesting exceeding maxDepth recursion limit', () => {
      let nested: any = { bottom: 'val' };
      for (let i = 0; i < 20; i++) {
        nested = { child: nested };
      }
      const message = { jsonrpc: '2.0', id: 2, method: 'tools/call', params: nested };
      const res = validator.validateInbound(message);
      expect(res.valid).toBe(false);
      expect(res.errorCode).toBe(-32600);
      expect(res.errorMessage).toContain('nesting depth limit');
    });

    it('rejects payloads exceeding total property key budget', () => {
      const fatParams: Record<string, number> = {};
      for (let i = 0; i < 60; i++) {
        fatParams[`key_${i}`] = i;
      }
      const message = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: fatParams };
      const res = validator.validateInbound(message);
      expect(res.valid).toBe(false);
      expect(res.errorCode).toBe(-32600);
      expect(res.errorMessage).toContain('key count budget');
    });

    it('enforces output amplification ceiling on outbound payloads', () => {
      const hugeData = 'A'.repeat(70 * 1024); // 70 KB > 64 KB limit
      const outbound = { jsonrpc: '2.0', id: 4, result: { data: hugeData } };
      const res = validator.validateOutbound(outbound);
      expect(res.valid).toBe(false);
      expect(res.errorCode).toBe(-32000);
      expect(res.errorMessage).toContain('OUTPUT_AMPLIFICATION_BLOCKED');
    });

    it('detects duplicate in-flight message IDs', () => {
      const msg1 = { jsonrpc: '2.0', id: 'req-unique-1', method: 'ping' };
      const msg2 = { jsonrpc: '2.0', id: 'req-unique-1', method: 'ping' };
      expect(validator.validateInbound(msg1).valid).toBe(true);
      const res2 = validator.validateInbound(msg2);
      expect(res2.valid).toBe(false);
      expect(res2.errorCode).toBe(-32600);
      expect(res2.errorMessage).toContain('Duplicate pending request id');
    });
  });

  describe('CapabilityManifestRegistry Contract Enforcement', () => {
    let registry: CapabilityManifestRegistry;

    beforeEach(() => {
      registry = new CapabilityManifestRegistry(true); // Default-deny unknown tools
    });

    it('blocks unregistered tools by default in strict mode (UNKNOWN_TOOL_BLOCKED)', () => {
      const decision = registry.verifyInvocation('unregistered_tool', {}, { shellExecution: true });
      expect(decision.authorized).toBe(false);
      expect(decision.reasonCode).toBe('UNKNOWN_TOOL_BLOCKED');
    });

    it('authorizes registered tool invocations matching granted capabilities', () => {
      const manifest: ToolCapabilityManifest = {
        toolName: 'safe_calculator',
        allowedCapabilities: {
          shellExecution: false,
          networkAccess: false,
          filesystemRead: false,
          filesystemWrite: false,
          processSpawn: false,
          destructiveOperation: false
        }
      };
      registry.registerManifest(manifest);

      const decision = registry.verifyInvocation('safe_calculator', { expr: '2+2' }, {});
      expect(decision.authorized).toBe(true);
      expect(decision.reasonCode).toBe('AUTHORIZED');
    });

    it('denies tool invocations exceeding declared capabilities (CAPABILITY_VIOLATION)', () => {
      const manifest: ToolCapabilityManifest = {
        toolName: 'linter',
        allowedCapabilities: {
          filesystemRead: true,
          shellExecution: false,
          networkAccess: false
        }
      };
      registry.registerManifest(manifest);

      const decision = registry.verifyInvocation(
        'linter',
        { command: 'cat /etc/passwd' },
        { shellExecution: true, filesystemRead: true }
      );
      expect(decision.authorized).toBe(false);
      expect(decision.reasonCode).toBe('CAPABILITY_VIOLATION');
      expect(decision.violatedCapability).toBe('shellExecution');
    });

    it('enforces directory path boundaries on filesystem arguments (PATH_SCOPE_VIOLATION)', () => {
      const allowedDir = path.resolve(os.tmpdir(), 'mcp-shield-allowed');
      const manifest: ToolCapabilityManifest = {
        toolName: 'project_editor',
        allowedCapabilities: { filesystemRead: true, filesystemWrite: true },
        allowedPaths: [allowedDir]
      };
      registry.registerManifest(manifest);

      // Outside directory
      const decisionOutside = registry.verifyInvocation(
        'project_editor',
        { path: path.resolve(os.tmpdir(), 'unauthorized.txt'), content: 'hello' },
        { filesystemWrite: true }
      );
      expect(decisionOutside.authorized).toBe(false);
      expect(decisionOutside.reasonCode).toBe('PATH_SCOPE_VIOLATION');

      // Inside directory
      const decisionInside = registry.verifyInvocation(
        'project_editor',
        { path: path.join(allowedDir, 'subfile.txt'), content: 'hello' },
        { filesystemWrite: true }
      );
      expect(decisionInside.authorized).toBe(true);
    });

    it('enforces egress domain allowlists on network destinations (EGRESS_SCOPE_VIOLATION)', () => {
      const manifest: ToolCapabilityManifest = {
        toolName: 'api_fetcher',
        allowedCapabilities: { networkAccess: true },
        allowedEgressDomains: ['api.github.com', 'raw.githubusercontent.com']
      };
      registry.registerManifest(manifest);

      const decisionBad = registry.verifyInvocation(
        'api_fetcher',
        { url: 'https://evil-exfiltration.com/data' },
        { networkAccess: true }
      );
      expect(decisionBad.authorized).toBe(false);
      expect(decisionBad.reasonCode).toBe('EGRESS_SCOPE_VIOLATION');

      const decisionGood = registry.verifyInvocation(
        'api_fetcher',
        { url: 'https://api.github.com/repos/rahulxcodex/mcp-shield' },
        { networkAccess: true }
      );
      expect(decisionGood.authorized).toBe(true);
    });
  });

  describe('Guards & Broker Interactions', () => {
    let session: SecuritySession;
    let canaryManager: CanaryManager;
    let cowFs: COWFileSystem;
    let ingressGuard: IngressGuard;
    let toolGuard: ToolGuard;
    let executionBroker: ExecutionBroker;
    let outputGuard: OutputGuard;
    let stagingDir: string;

    beforeEach(async () => {
      session = new SecuritySession({ rules: [] } as any, 'node', ['-e', 'console.log()']);
      await session.start();
      canaryManager = new CanaryManager();
      stagingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-shield-broker-test-'));
      cowFs = new COWFileSystem(stagingDir);
      ingressGuard = new IngressGuard(session, canaryManager);
      toolGuard = new ToolGuard(session);
      executionBroker = new ExecutionBroker(session, cowFs);
      outputGuard = new OutputGuard(session, canaryManager);
    });

    afterEach(() => {
      try {
        fs.rmSync(stagingDir, { recursive: true, force: true });
      } catch {}
    });

    it('IngressGuard rejects non-initialize calls when session is in INITIALIZING state', () => {
      session.transitionState('INITIALIZING');
      expect(session.getState()).toBe('INITIALIZING');
      const toolCall = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'calc' } };
      const res = ingressGuard.checkStatePrerequisites(toolCall);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Server is not ready');
    });

    it('ToolGuard analyzes candidate commands and flags shell injection', () => {
      const maliciousArgs = {
        target: 'test',
        code: 'rm -rf /'
      };
      const result = toolGuard.analyzeToolParameters('runner', maliciousArgs, true);
      expect(result.isSafe).toBe(false);
      expect(result.blockReason?.toLowerCase()).toContain('blocked');
    });

    it('OutputGuard injects canaries and pins tools list snapshot', () => {
      session.transitionState('INITIALIZING');
      session.transitionState('READY');
      const rawTools = [
        { name: 'read_doc', description: 'Reads documents', inputSchema: {} }
      ];
      const outboundMessage = {
        jsonrpc: '2.0',
        id: 10,
        result: { tools: rawTools }
      };

      const buf = Buffer.from(JSON.stringify(outboundMessage), 'utf8');
      const res = outputGuard.processOutboundMessage(buf, () => {}, () => {});
      expect(res.allowed).toBe(true);
      expect(res.message.result.tools.length).toBeGreaterThan(1); // Canary injected
      expect(session.toolRegistry.has('read_doc')).toBe(true);
    });

    it('LifecycleManager sanitizes execution environment by removing sensitive tokens and injection vectors', () => {
      const dirtyEnv = {
        PATH: '/bin',
        OPENAI_API_KEY: 'sk-1234567890',
        LD_PRELOAD: '/lib/evil.so',
        AWS_SECRET_ACCESS_KEY: 'supersecret',
        USER: 'alice'
      };
      const cleanEnv = LifecycleManager.buildSafeEnv(dirtyEnv);
      expect(cleanEnv.PATH).toBe('/bin');
      expect(cleanEnv.USER).toBe('alice');
      expect(cleanEnv.OPENAI_API_KEY).toBeUndefined();
      expect(cleanEnv.LD_PRELOAD).toBeUndefined();
      expect(cleanEnv.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(cleanEnv.PYTHONUNBUFFERED).toBe('1');
    });
  });
});
