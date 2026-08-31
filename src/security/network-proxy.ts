import * as http from 'http';
import * as net from 'net';
import * as dns from 'dns';
import { promisify } from 'util';
import { PolicyEngine } from './policy-engine';

const lookup = promisify(dns.lookup);

export class NetworkEgressProxy {
  private server: http.Server;
  private port: number = 0;

  constructor(private policyEngine: PolicyEngine) {
    this.server = http.createServer(this.handleHttpRequest.bind(this));
    this.server.on('connect', this.handleConnectRequest.bind(this));
  }

  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.listen(0, '127.0.0.1', () => {
        const address = this.server.address() as net.AddressInfo;
        this.port = address.port;
        resolve(this.port);
      });
      this.server.on('error', reject);
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }

  public getPort(): number {
    return this.port;
  }

  private async isAllowed(hostname: string): Promise<string | null> {
    try {
      // Resolve IP to prevent DNS rebinding
      const { address } = await lookup(hostname);
      
      // We can use a mocked args object to pass to checkEgress
      const egressCheck = this.policyEngine.checkEgress({ url: `http://${address}` });
      if (egressCheck.isBlocked) return null;

      const domainCheck = this.policyEngine.checkEgress({ url: `http://${hostname}` });
      if (domainCheck.isBlocked) return null;

      return address;
    } catch {
      return null; // Block if DNS fails
    }
  }

  private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    if (!req.url) {
      res.writeHead(400);
      res.end('Bad Request');
      return;
    }
    
    try {
      const url = new URL(req.url);
      const resolvedIp = await this.isAllowed(url.hostname);
      if (!resolvedIp) {
        res.writeHead(403);
        res.end('Blocked by MCP-Shield Egress Policy');
        return;
      }

      const options = {
        hostname: resolvedIp,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: req.method,
        headers: req.headers
      };
      
      // Ensure the Host header is explicitly set to the original hostname
      // to preserve virtual hosting and SNI behaviors downstream if applicable.
      options.headers.host = url.host;

      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
      });

      proxyReq.on('error', (err) => {
        res.writeHead(502);
        res.end('Bad Gateway');
      });

      req.pipe(proxyReq, { end: true });
    } catch {
      res.writeHead(400);
      res.end('Invalid URL');
    }
  }

  private async handleConnectRequest(req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) {
    if (!req.url) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }

    const [hostname, port] = req.url.split(':');
    const resolvedIp = await this.isAllowed(hostname);

    if (!resolvedIp) {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }

    const serverSocket = net.connect(parseInt(port) || 443, resolvedIp, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
                         'Proxy-agent: MCP-Shield\r\n\r\n');
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', (err) => {
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
    });

    clientSocket.on('error', () => {
      serverSocket.end();
    });
  }
}

