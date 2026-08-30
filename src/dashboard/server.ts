import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as crypto from 'crypto';

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

    this.app.use((req, res, next) => {
      if (req.query.token !== this.authToken) {
        res.status(401).send('Unauthorized: Invalid or missing token parameter.');
        return;
      }
      next();
    });

    this.app.get('/', (req, res) => {
      res.send(`
        <html>
        <head><title>MCP-Shield Dashboard</title></head>
        <body style="font-family: sans-serif; background: #1e1e1e; color: #fff; padding: 20px;">
          <h1>🛡️ MCP-Shield Live Audit</h1>
          <div id="logs" style="background: #000; padding: 10px; border-radius: 5px; height: 500px; overflow-y: auto; font-family: monospace;"></div>
          <script>
            const host = window.location.host;
            const wsProtocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const token = new URLSearchParams(window.location.search).get('token');
            const ws = new WebSocket(wsProtocol + host + '/?token=' + token);
            const logs = document.getElementById('logs');
            ws.onmessage = (event) => {
              const data = JSON.parse(event.data);
              const div = document.createElement('div');
              div.style.padding = '5px';
              div.style.borderBottom = '1px solid #333';
              
              let color = '#0f0';
              if (data.type.includes('blocked') || data.type.includes('exceeded') || data.type.includes('quarantine')) {
                color = '#f00';
              }
              
              const escapeHtml = (unsafe) => {
                return (unsafe || '').toString()
                     .replace(/&/g, "&amp;")
                     .replace(/</g, "&lt;")
                     .replace(/>/g, "&gt;")
                     .replace(/"/g, "&quot;")
                     .replace(/'/g, "&#039;");
              };
              
              const safeToolName = escapeHtml(data.toolName);
              const safeReason = escapeHtml(data.reason);
              const safeType = escapeHtml(data.type).toUpperCase();
              const safeTimestamp = escapeHtml(data.timestamp);
              
              div.innerHTML = \`<span style="color: \${color}">[\${safeTimestamp}] \${safeType}</span> \${safeToolName ? 'Tool: ' + safeToolName : ''} \${safeReason ? '<br/>Reason: ' + safeReason : ''}\`;
              logs.prepend(div);
            };
          </script>
        </body>
        </html>
      `);
    });

    // Enforce Origin Check against Cross-Site WebSocket Hijacking (CSWSH) and Token Auth
    this.wss.on('connection', (ws, req) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      if (url.searchParams.get('token') !== this.authToken) {
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

  public start() {
    this.server.on('error', (err: any) => {
      console.error(`[MCP-SHIELD] Dashboard server error: ${err.message}`);
    });

    this.wss.on('error', (err: any) => {
      console.error(`[MCP-SHIELD] WebSocket server error: ${err.message}`);
    });

    try {
      this.server.listen(this.port, '127.0.0.1', () => {
        const addr = this.server.address();
        if (addr && typeof addr === 'object') {
          this.actualPort = addr.port;
        }
        console.error(`[MCP-SHIELD] Real-time Dashboard running at http://127.0.0.1:${this.getPort()}/?token=${this.authToken}`);
      });
    } catch (e: any) {
      console.error(`[MCP-SHIELD] Dashboard failed to listen: ${e.message}`);
    }
  }

  public broadcast(event: any) {
    const payload = { timestamp: new Date().toISOString(), ...event };
    const message = JSON.stringify(payload);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN && client.bufferedAmount < 64 * 1024) {
        client.send(message);
      }
    }
  }

  public stop(): void {
    for (const client of this.clients) {
      try { client.close(); } catch {}
    }
    this.clients.clear();
    try { this.wss.close(); } catch {}
    try {
      if (typeof (this.server as any).closeAllConnections === 'function') {
        (this.server as any).closeAllConnections();
      }
      this.server.close();
    } catch {}
  }
}
