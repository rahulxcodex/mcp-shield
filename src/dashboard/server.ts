import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as crypto from 'crypto';
import { getDashboardHtml } from './html-template';

export class DashboardServer {
  private app = express();
  private server = http.createServer(this.app);
  private wss = new WebSocketServer({ server: this.server });
  private clients = new Set<WebSocket>();
  private actualPort: number = 0;
  private authToken: string;

  constructor(private port: number = process.env.MCP_SHIELD_DASHBOARD_PORT ? parseInt(process.env.MCP_SHIELD_DASHBOARD_PORT, 10) : 3333) {
    this.actualPort = this.port;
    this.authToken = process.env.MCP_SHIELD_DASHBOARD_TOKEN || crypto.randomBytes(16).toString('hex');

    const parseCookies = (cookieHeader?: string): Record<string, string> => {
      const cookies: Record<string, string> = {};
      if (!cookieHeader) return cookies;
      for (const item of cookieHeader.split(';')) {
        const [k, v] = item.trim().split('=');
        if (k && v) cookies[k] = decodeURIComponent(v);
      }
      return cookies;
    };

    this.app.use((req, res, next) => {
      const cookies = parseCookies(req.headers.cookie);
      const authHeader = req.headers.authorization;
      const bearerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

      // 1. If query parameter token is present and valid: set HttpOnly session cookie & redirect to /
      if (req.query.token === this.authToken) {
        res.setHeader('Set-Cookie', `mcp_shield_session=${this.authToken}; HttpOnly; SameSite=Strict; Path=/`);
        // Redirect to root path without query string to eliminate token leakage in browser history/logs/referrers
        res.redirect(302, '/');
        return;
      }

      // 2. Validate session cookie or bearer token
      if (cookies['mcp_shield_session'] === this.authToken || bearerToken === this.authToken) {
        return next();
      }

      res.status(401).send('Unauthorized: Invalid or missing session credentials.');
    });

    this.app.get('/', (req, res) => {
      res.setHeader('Content-Type', 'text/html');
      res.send(getDashboardHtml(this.authToken, this.getPort()));
    });

    // Cross-Site WebSocket Hijacking Protection & Multi-Factor Auth (Cookie / Query / Header)
    this.wss.on('connection', (ws, req) => {
      const cookies = parseCookies(req.headers.cookie);
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const tokenParam = url.searchParams.get('token');
      const hasValidAuth =
        cookies['mcp_shield_session'] === this.authToken ||
        tokenParam === this.authToken;

      if (!hasValidAuth) {
        ws.close(4001, 'Unauthorized: Invalid token');
        return;
      }

      const origin = req.headers.origin;
      const boundPort = this.getPort();
      const allowedOrigins = [
        `http://127.0.0.1:${boundPort}`,
        `http://localhost:${boundPort}`,
        `http://[::1]:${boundPort}`
      ];

      if (origin && !allowedOrigins.includes(origin)) {
        ws.close(4003, 'Forbidden: Cross-Origin WebSocket Connection Rejected');
        return;
      }

      this.clients.add(ws);
      ws.on('close', () => this.clients.delete(ws));
    });
  }

  public getPort(): number {
    return this.actualPort || this.port;
  }

  public getAuthToken(): string {
    return this.authToken;
  }

  public getUrl(): string {
    return `http://localhost:${this.getPort()}/?token=${this.authToken}`;
  }

  public start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, '127.0.0.1', () => {
        const address = this.server.address();
        if (address && typeof address === 'object') {
          this.actualPort = address.port;
        }
        resolve(this.actualPort);
      });
      this.server.on('error', reject);
    });
  }

  public broadcast(event: any): void {
    const payload = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      for (const client of this.clients) {
        try { client.close(); } catch {}
      }
      try {
        if (typeof (this.server as any).closeAllConnections === 'function') {
          (this.server as any).closeAllConnections();
        }
      } catch {}
      this.wss.close(() => {
        this.server.close(() => resolve());
      });
    });
  }
}
