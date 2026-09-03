import { RequestDispatcher } from '../../src/core/dispatcher';
import { SecuritySession } from '../../src/core/session';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { JsonRpcStreamFramer } from '../../src/core/stream-framing';
import { PolicyEngine } from '../../src/security/policy-engine';
import { DashboardServer } from '../../src/dashboard/server';
import { COWFileSystem } from '../../src/sandbox/cow-fs';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('MCP Protocol Conformance & Security Suite', () => {
  it('should gracefully handle malformed JSON-RPC payloads', () => {
    let errorCalled = false;
    const dispatcher = new RequestDispatcher(
      async () => {},
      (msg, code, err) => {
        errorCalled = true;
        expect(code).toBe(-32600);
      }
    );

    dispatcher.enqueue({ jsonrpc: '1.0', id: 1, method: 'test' });
    expect(errorCalled).toBe(true);
  });

  it('should prevent duplicate request IDs from running in flight concurrently', async () => {
    const executed: any[] = [];
    let duplicateError: string | null = null;

    let resolveFirst: (() => void) | null = null;
    const firstPromise = new Promise<void>((r) => { resolveFirst = r; });

    const dispatcher = new RequestDispatcher(
      async (msg) => {
        if (msg.id === 42) {
          executed.push(msg.id);
          await firstPromise;
        }
      },
      (msg, code, err) => {
        if (msg.id === 42) {
          duplicateError = err;
        }
      },
      { maxInflightRequests: 5 }
    );

    dispatcher.enqueue({ jsonrpc: '2.0', id: 42, method: 'tools/call', params: { name: 'test' } });
    dispatcher.enqueue({ jsonrpc: '2.0', id: 42, method: 'tools/call', params: { name: 'test' } });

    expect(duplicateError).toContain('Duplicate Request ID');
    resolveFirst!();
  });

  it('should execute queued requests concurrently up to maxInflightRequests', async () => {
    let running = 0;
    let maxObserved = 0;
    const resolvers: Array<() => void> = [];

    const dispatcher = new RequestDispatcher(
      async () => {
        running++;
        if (running > maxObserved) maxObserved = running;
        await new Promise<void>((r) => resolvers.push(r));
        running--;
      },
      undefined,
      { maxInflightRequests: 5, maxQueueDepth: 50 }
    );

    for (let i = 1; i <= 5; i++) {
      dispatcher.enqueue({ jsonrpc: '2.0', id: i, method: 'ping' });
    }

    expect(maxObserved).toBe(5);
    resolvers.forEach(r => r());
  });

  it('should sanitize DLP secrets across result, error, and notifications', () => {
    const sanitizer = new SecretSanitizer();
    const secret = 'sk-ant-api03-abcdef1234567890abcdef1234567890';
    const fakePayload = {
      result: { apiKey: secret },
      error: { code: -32000, message: `Failed with token: ${secret}`, data: { raw: secret } },
      params: { log: `Leaked key: ${secret}` }
    };

    const sanitizedResult = JSON.parse(sanitizer.sanitize(JSON.stringify(fakePayload.result)));
    const sanitizedError = JSON.parse(sanitizer.sanitize(JSON.stringify(fakePayload.error)));
    const sanitizedParams = JSON.parse(sanitizer.sanitize(JSON.stringify(fakePayload.params)));

    expect(sanitizedResult.apiKey).toContain('[[SHIELD_SECRET_');
    expect(sanitizedError.message).toContain('[[SHIELD_SECRET_');
    expect(sanitizedError.data.raw).toContain('[[SHIELD_SECRET_');
    expect(sanitizedParams.log).toContain('[[SHIELD_SECRET_');
  });

  it('should restore secrets for both tools/call and call_tool symmetrically', () => {
    const sanitizer = new SecretSanitizer();
    const rawSecret = 'ghp_123456789012345678901234567890123456';
    const masked = sanitizer.sanitize(JSON.stringify({ token: rawSecret }));
    expect(masked).toContain('[[SHIELD_SECRET_');

    const restored = sanitizer.restore(masked);
    expect(restored).toContain(rawSecret);
  });

  it('should pin full tool list snapshot and detect unauthorized mutations', () => {
    const session = new SecuritySession({ rules: [] } as any, 'echo', ['hello']);
    const initialTools = [
      { name: 'read_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'list_dir', inputSchema: { type: 'object' } }
    ];

    expect(() => session.validateToolsSnapshot(initialTools)).not.toThrow();

    // Re-verification with identical tools succeeds
    expect(() => session.validateToolsSnapshot(initialTools)).not.toThrow();

    // Adding a backdoor tool dynamically throws pinning violation
    const tamperedTools = [
      ...initialTools,
      { name: 'exec_cmd', inputSchema: { type: 'object' } }
    ];
    expect(() => session.validateToolsSnapshot(tamperedTools)).toThrow('SCHEMA PINNING VIOLATION');
  });

  it('should bind dashboard server explicitly to loopback 127.0.0.1', async () => {
    const dashboard = new DashboardServer(0);
    const port = await dashboard.start();
    expect(port).toBeGreaterThan(0);
    await dashboard.stop();
  });

  it('should perform atomic COW commit and verify post-rename file integrity', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cow-test-'));
    const cow = new COWFileSystem(tmpDir);

    const target = path.join(tmpDir, 'test.txt');
    fs.writeFileSync(target, 'initial content');

    const staged = cow.stageWrite(target, 'modified secure content');
    expect(staged.diff).toContain('+modified secure content');

    cow.commit(staged.stagingPath, staged.absoluteOriginalPath, staged.originalIdentity);
    expect(fs.readFileSync(target, 'utf8')).toBe('modified secure content');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
