import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

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

describe('End-to-End MCP-Shield Proxy Integration Test Suite', () => {
  let proxyProcess: ChildProcess;
  let client: MCPTestClient;

  const mockServerPath = path.resolve(__dirname, '../fixtures/mock-mcp-server.js');
  const binPath = path.resolve(__dirname, '../../bin/mcp-shield.js');

  beforeAll((done) => {
    // Spawn shared MCP-Shield instance wrapping mock MCP server
    proxyProcess = spawn(process.execPath, [binPath, 'wrap', '--', process.execPath, mockServerPath], {
      cwd: path.resolve(__dirname, '../..'),
      env: {
        ...process.env,
        MCP_SHIELD_DASHBOARD_PORT: '0',
        MCP_SHIELD_HONEY_TOKENS: 'mcp_honey_decoy_secret_key_123'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    client = new MCPTestClient(proxyProcess);
    setTimeout(done, 2000);
  });

  afterAll(() => {
    client.close();
  });

  it('E2E-01: Completes standard MCP handshake (initialize -> initialized -> tools/list)', async () => {
    // 1. Initialize
    const initResponse = await client.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        clientInfo: { name: 'claude-desktop-simulator', version: '1.0.0' },
        capabilities: {}
      }
    });

    expect(initResponse).toBeDefined();
    expect(initResponse.id).toBe(1);
    expect(initResponse.result?.serverInfo?.name).toBe('mock-mcp-server');

    // 2. Initialized notification
    client.sendRaw(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    // 3. List Tools
    const toolsResponse = await client.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {}
    });

    expect(toolsResponse.id).toBe(2);
    expect(toolsResponse.result?.tools).toBeInstanceOf(Array);
    expect(toolsResponse.result.tools.length).toBeGreaterThan(0);
  });

  it('E2E-02: Forwards benign tool invocations and returns execution result', async () => {
    const response = await client.send({
      jsonrpc: '2.0',
      id: 3,
      method: 'call_tool',
      params: {
        name: 'echo_tool',
        arguments: { message: 'Zero Trust Gateway Active' }
      }
    });

    expect(response.id).toBe(3);
    expect(response.result?.content[0]?.text).toBe('echo: Zero Trust Gateway Active');
  });

  it('E2E-03: Blocks destructive shell commands at Gateway and returns JSON-RPC error without reaching downstream server', async () => {
    const response = await client.send({
      jsonrpc: '2.0',
      id: 4,
      method: 'call_tool',
      params: {
        name: 'execute_cmd',
        arguments: {
          cmd: 'rm -rf /'
        }
      }
    });

    expect(response.id).toBe(4);
    expect(response.error).toBeDefined();
    expect(response.error.code).toBe(-32000);
    expect(response.error.message.toUpperCase()).toContain('AST FIREWALL BLOCKED');
    expect(response.error.message).toContain('Destructive root deletion blocked');
  });

  it('E2E-04: Blocks egress exfiltration to blacklisted domains', async () => {
    const response = await client.send({
      jsonrpc: '2.0',
      id: 5,
      method: 'call_tool',
      params: {
        name: 'fetch_data',
        arguments: {
          url: 'https://c2.evil.com/exfiltrate-data'
        }
      }
    });

    expect(response.id).toBe(5);
    expect(response.error).toBeDefined();
    expect(response.error.code).toBe(-32000);
    expect(response.error.message).toContain('EGRESS FIREWALL BLOCKED');
    expect(response.error.message).toContain('evil.com');
  });

  it('E2E-05: Redacts sensitive cloud provider credentials from downstream tool outputs (DLP)', async () => {
    const response = await client.send({
      jsonrpc: '2.0',
      id: 6,
      method: 'call_tool',
      params: {
        name: 'leak_credentials',
        arguments: {}
      }
    });

    expect(response.id).toBe(6);
    expect(response.result).toBeDefined();
    const resultText = response.result.content[0].text;
    
    // AWS key and OpenAI key should be redacted with tokens
    expect(resultText).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(resultText).not.toContain('sk-proj-1234567890abcdef1234567890abcdef1234567890');
    expect(resultText).toContain('[[SHIELD_SECRET_');
  });

  it('E2E-06: Enforces rate-limiting ceiling on high-frequency tool calls', async () => {
    const toolName = 'rate_test_tool';
    
    // Send 15 calls (limit is 15)
    for (let i = 100; i < 115; i++) {
      const res = await client.send({
        jsonrpc: '2.0',
        id: i,
        method: 'call_tool',
        params: { name: toolName, arguments: { message: `req_${i}` } }
      });
      expect(res.result).toBeDefined();
    }

    // 16th call must be blocked
    const blockedRes = await client.send({
      jsonrpc: '2.0',
      id: 116,
      method: 'call_tool',
      params: { name: toolName, arguments: { message: 'should be blocked' } }
    });

    expect(blockedRes.id).toBe(116);
    expect(blockedRes.error).toBeDefined();
    expect(blockedRes.error.code).toBe(-32000);
    expect(blockedRes.error.message).toContain('RATE LIMIT EXCEEDED');
  });

  it('E2E-07: Recovers from malformed JSON in stream without corrupting subsequent valid requests', async () => {
    // Send broken JSON frame
    client.sendRaw('{"jsonrpc":"2.0", incomplete_json\n');

    // Follow up immediately with valid request
    const response = await client.send({
      jsonrpc: '2.0',
      id: 200,
      method: 'call_tool',
      params: { name: 'echo_tool', arguments: { message: 'Recovered after malformed stream chunk' } }
    });

    // Proxy forwards valid request
    expect(response.id).toBe(200);
    expect(response.result?.content[0]?.text).toBe('echo: Recovered after malformed stream chunk');
  });

  it('E2E-08: Downstream child process abrupt crash exits proxy with corresponding exit code', (done) => {
    const crashProxy = spawn(process.execPath, [binPath, 'wrap', '--', process.execPath, mockServerPath], {
      cwd: path.resolve(__dirname, '../..'),
      env: {
        ...process.env,
        MCP_SHIELD_DASHBOARD_PORT: '0'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    crashProxy.on('exit', (code) => {
      expect(code).toBe(42);
      done();
    });

    setTimeout(() => {
      crashProxy.stdin?.write(JSON.stringify({
        jsonrpc: '2.0',
        id: 999,
        method: 'call_tool',
        params: { name: 'crash_server', arguments: {} }
      }) + '\n');
    }, 1200);
  });

  it('E2E-09: Generates cryptographically tamper-evident audit log with intact SHA-256 hash chains', () => {
    const logsDir = path.resolve(__dirname, '../../.mcp-shield/logs');
    expect(fs.existsSync(logsDir)).toBe(true);
    const files = fs.readdirSync(logsDir).filter((f: string) => f.endsWith('.jsonl')).sort();
    expect(files.length).toBeGreaterThan(0);
    const latestLog = path.join(logsDir, files[files.length - 1]);

    const lines = fs.readFileSync(latestLog, 'utf8').trim().split('\n').filter(Boolean);
    let prevHash = 'GENESIS';

    const canonicalStringify = (obj: any): string => {
      if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
      if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
      const keys = Object.keys(obj).sort();
      return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
    };

    for (const line of lines) {
      const entry = JSON.parse(line);
      expect(entry.previousHash).toBe(prevHash);
      const computedHash = crypto.createHash('sha256').update(prevHash + canonicalStringify(entry.data)).digest('hex');
      expect(entry.hash).toBe(computedHash);
      prevHash = entry.hash;
    }
  });
});
