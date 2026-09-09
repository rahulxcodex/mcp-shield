import * as http from 'http';
import { NetworkEgressProxy } from '../../src/security/network-proxy';
import { PolicyEngine } from '../../src/security/policy-engine';
import { ConfigLoader } from '../../src/security/config';

describe('NetworkEgressProxy Redirect Containment & SSRF Defense', () => {
  let mockServer: http.Server;
  let mockPort: number;
  let proxy: NetworkEgressProxy;
  let proxyPort: number;

  beforeAll(async () => {
    mockServer = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://127.0.0.1:${mockPort}`);

      if (url.pathname === '/target-ok') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'success', hop: 'destination' }));
        return;
      }

      if (url.pathname === '/redirect-ok') {
        res.writeHead(302, { Location: `http://127.0.0.1:${mockPort}/target-ok` });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-metadata') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-loop-a') {
        res.writeHead(302, { Location: `http://127.0.0.1:${mockPort}/redirect-loop-b` });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-loop-b') {
        res.writeHead(302, { Location: `http://127.0.0.1:${mockPort}/redirect-loop-a` });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-unsupported-proto') {
        res.writeHead(302, { Location: 'gopher://127.0.0.1:70/' });
        res.end();
        return;
      }

      if (url.pathname.startsWith('/chain-')) {
        const step = parseInt(url.pathname.replace('/chain-', ''), 10);
        if (step > 6) {
          res.writeHead(200);
          res.end('Chain complete');
        } else {
          res.writeHead(302, { Location: `http://127.0.0.1:${mockPort}/chain-${step + 1}` });
          res.end();
        }
        return;
      }

      res.writeHead(404);
      res.end('Not Found');
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        mockPort = (mockServer.address() as any).port;
        resolve();
      });
    });

    const baseConfig = ConfigLoader.getHardenedProfile();
    const config = {
      ...baseConfig,
      egress: {
        ...baseConfig.egress,
        enabled: true,
        allowMode: 'allow' as const,
        allowPrivateNetworks: true,
        blockLoopback: false,
        blockLinkLocal: true,
        blockMetadataEndpoints: true
      }
    };

    const policyEngine = new PolicyEngine(config);
    proxy = new NetworkEgressProxy(policyEngine);
    proxyPort = await proxy.start();
  });

  afterAll(async () => {
    if (proxy) await proxy.stop();
    if (mockServer) {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()));
    }
  });

  function makeProxiedRequest(path: string): Promise<{ statusCode: number; body: string; headers: http.IncomingHttpHeaders }> {
    return new Promise((resolve, reject) => {
      const targetUrl = `http://127.0.0.1:${mockPort}${path}`;
      const options: http.RequestOptions = {
        hostname: '127.0.0.1',
        port: proxyPort,
        path: targetUrl,
        method: 'GET',
        headers: {
          Host: `127.0.0.1:${mockPort}`
        }
      };

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
            headers: res.headers
          });
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  test('transparently follows internal 302 redirect and returns 200 with terminal payload to child', async () => {
    const res = await makeProxiedRequest('/redirect-ok');
    expect(res.statusCode).toBe(200);
    const data = JSON.parse(res.body);
    expect(data.status).toBe('success');
    expect(data.hop).toBe('destination');
  });

  test('blocks SSRF redirect-hop into cloud metadata (169.254.169.254) with 403 Forbidden', async () => {
    const res = await makeProxiedRequest('/redirect-metadata');
    expect(res.statusCode).toBe(403);
    expect(res.body).toContain('Blocked by MCP-Shield Egress Policy: Unauthorized Redirect Target');
  });

  test('detects redirect loops and terminates with 508 Loop Detected', async () => {
    const res = await makeProxiedRequest('/redirect-loop-a');
    expect(res.statusCode).toBe(508);
    expect(res.body).toContain('Redirect Loop Detected');
  });

  test('terminates runaway redirect chains (>5 hops) with 508 Maximum Redirects Exceeded', async () => {
    const res = await makeProxiedRequest('/chain-1');
    expect(res.statusCode).toBe(508);
    expect(res.body).toContain('Maximum Redirects Exceeded');
  });

  test('rejects redirects to unsupported protocols (e.g. gopher://) with 400 Bad Request', async () => {
    const res = await makeProxiedRequest('/redirect-unsupported-proto');
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Unsupported Redirect Protocol');
  });
});
