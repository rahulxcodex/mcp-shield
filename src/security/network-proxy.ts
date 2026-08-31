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
      // Strip brackets if IPv6 literal
      const cleanHostname = hostname.replace(/^\[|\]$/g, '');

      // Resolve IP to prevent DNS rebinding TOCTOU
      const { address } = await lookup(cleanHostname);
      
      // Check egress rules against both resolved IP and original hostname
      const egressCheck = this.policyEngine.checkEgress({ url: `http://${address}` });
      if (egressCheck.isBlocked) return null;

      const domainCheck = this.policyEngine.checkEgress({ url: `http://${cleanHostname}` });
      if (domainCheck.isBlocked) return null;

      return address;
    } catch {
      return null; // Fail closed if DNS resolution fails
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

      // Pin strictly to resolved IP to prevent DNS rebinding TOCTOU
      const options = {
        hostname: resolvedIp,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: req.method,
        headers: { ...req.headers }
      };
      
      // Preserve original Host header for virtual hosting and downstream routing
      options.headers.host = url.host;

      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
      });

      proxyReq.on('error', () => {
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

    const [rawHost, rawPort] = req.url.split(':');
    const targetPort = parseInt(rawPort, 10) || 443;
    const resolvedIp = await this.isAllowed(rawHost);

    if (!resolvedIp) {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }

    // Connect strictly to resolved IP address (pinned)
    const serverSocket = net.connect({ host: resolvedIp, port: targetPort }, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
                         'Proxy-agent: MCP-Shield\r\n\r\n');
      if (head && head.length > 0) {
        serverSocket.write(head);
      }
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', () => {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });

    clientSocket.on('error', () => {
      serverSocket.end();
    });
  }
}

