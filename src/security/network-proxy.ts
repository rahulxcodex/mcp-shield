import * as http from 'http';
import * as net from 'net';
import * as dns from 'dns';
import { PolicyEngine } from './policy-engine';
import { IpClassifier, EgressSecurityConfig } from './ip-utils';

/**
 * Safely parses an HTTP CONNECT authority string.
 * Handles `[IPv6]:port`, `[IPv6]`, `hostname:port`, and `ipv4:port`.
 * Rejects malformed authorities.
 */
export function parseConnectAuthority(authority: string): { host: string; port: number } | null {
  if (!authority || typeof authority !== 'string') return null;
  const clean = authority.trim();
  if (clean.length === 0) return null;

  // Format 1: [IPv6]:port or [IPv6]
  if (clean.startsWith('[')) {
    const closingBracket = clean.indexOf(']');
    if (closingBracket === -1) return null; // Malformed IPv6 literal
    const host = clean.substring(1, closingBracket);
    const rest = clean.substring(closingBracket + 1);
    let port = 443;
    if (rest.startsWith(':')) {
      const p = parseInt(rest.slice(1), 10);
      if (isNaN(p) || p <= 0 || p > 65535) return null;
      port = p;
    } else if (rest.length > 0) {
      return null; // Malformed trailing data
    }
    return { host, port };
  }

  // Format 2: host:port or host (IPv4 or regular hostname)
  const colonCount = (clean.match(/:/g) || []).length;
  if (colonCount === 1) {
    const [host, portStr] = clean.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port <= 0 || port > 65535) return null;
    return { host, port };
  } else if (colonCount === 0) {
    return { host: clean, port: 443 };
  }

  // Unbracketed IPv6 with multiple colons is invalid in CONNECT authority
  return null;
}

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

  /**
   * Evaluates hostname and resolves all IPv4 & IPv6 addresses.
   * Rejects if ANY resolved address violates the egress security policy.
   * Returns the pinned IP to connect to if allowed, or null if blocked.
   */
  public async isAllowed(hostname: string): Promise<string | null> {
    try {
      const config = this.policyEngine.getConfig();
      const egressConfig = config.egress as EgressSecurityConfig;

      // Strip brackets if IPv6 literal
      const cleanHostname = hostname.replace(/^\[|\]$/g, '').trim().toLowerCase();

      // 1. Direct check on hostname / literal IP
      const directCheck = IpClassifier.checkEgressViolation(cleanHostname, egressConfig);
      if (directCheck.isBlocked) {
        return null;
      }

      // If it's already an IP literal or alternate encoding, evaluate normalized form
      const normalizedDirect = IpClassifier.normalizeIp(cleanHostname);
      if (normalizedDirect.underlyingIpv4 || net.isIP(normalizedDirect.normalized)) {
        const targetIp = normalizedDirect.underlyingIpv4 || normalizedDirect.normalized;
        const ipCheck = IpClassifier.checkEgressViolation(targetIp, egressConfig);
        if (ipCheck.isBlocked) return null;
        return targetIp;
      }

      // 2. DNS Resolution: Query ALL A and AAAA addresses to prevent multi-homed / DNS rebinding attacks
      const resolvedRecords = await dns.promises.lookup(cleanHostname, { all: true });
      if (!resolvedRecords || resolvedRecords.length === 0) {
        return null; // Fail-closed if no DNS records
      }

      const validAddresses: string[] = [];

      // Verify EVERY resolved address. If any single IP violates policy, reject entire request!
      for (const record of resolvedRecords) {
        const rawAddr = record.address;
        const normalized = IpClassifier.normalizeIp(rawAddr);
        const targetIp = normalized.underlyingIpv4 || normalized.normalized;

        const check = IpClassifier.checkEgressViolation(targetIp, egressConfig);
        if (check.isBlocked) {
          return null; // One resolved address violates policy -> Fail closed!
        }

        // Also check via policy engine argument check for custom rules
        const policyCheck = this.policyEngine.checkEgress({ url: `http://${targetIp}` });
        if (policyCheck.isBlocked) {
          return null;
        }

        validAddresses.push(targetIp);
      }

      // Return the first pinned, verified address
      return validAddresses[0] || null;
    } catch {
      return null; // Fail closed on DNS lookup errors
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
      const pinnedIp = await this.isAllowed(url.hostname);
      if (!pinnedIp) {
        res.writeHead(403);
        res.end('Blocked by MCP-Shield Egress Policy');
        return;
      }

      // Pin strictly to resolved IP to prevent DNS rebinding TOCTOU
      const isIpv6 = net.isIPv6(pinnedIp);
      const targetHost = isIpv6 ? `[${pinnedIp}]` : pinnedIp;

      // Preserve original Host header for virtual hosting
      const headers: http.OutgoingHttpHeaders = { ...(req.headers as any), host: url.host };

      const options: http.RequestOptions = {
        hostname: pinnedIp,
        host: targetHost,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: req.method,
        headers
      };

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

    const parsedAuthority = parseConnectAuthority(req.url);
    if (!parsedAuthority) {
      clientSocket.end('HTTP/1.1 400 Bad Request: Malformed CONNECT Authority\r\n\r\n');
      return;
    }

    const { host: rawHost, port: targetPort } = parsedAuthority;
    const pinnedIp = await this.isAllowed(rawHost);

    if (!pinnedIp) {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }

    // Connect strictly to the pinned, verified resolved IP address
    const serverSocket = net.connect({ host: pinnedIp, port: targetPort }, () => {
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
