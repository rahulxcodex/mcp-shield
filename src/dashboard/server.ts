import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';

export class DashboardServer {
  private app = express();
  private server = http.createServer(this.app);
  private wss = new WebSocketServer({ server: this.server });
  private clients = new Set<WebSocket>();

  constructor(private port: number = 3333) {
    this.app.get('/', (req, res) => {
      res.send(`
        <html>
        <head><title>MCP-Shield Dashboard</title></head>
        <body style="font-family: sans-serif; background: #1e1e1e; color: #fff; padding: 20px;">
          <h1>🛡️ MCP-Shield Live Audit</h1>
          <div id="logs" style="background: #000; padding: 10px; border-radius: 5px; height: 500px; overflow-y: auto; font-family: monospace;"></div>
          <script>
            const ws = new WebSocket('ws://localhost:${this.port}');
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

    // Enforce Origin Check against Cross-Site WebSocket Hijacking (CSWSH)
    this.wss.on('connection', (ws, req) => {
      const origin = req.headers.origin;
      const allowedOrigins = [`http://127.0.0.1:${this.port}`, `http://localhost:${this.port}`];

      if (origin && !allowedOrigins.includes(origin)) {
        ws.close(4003, 'Forbidden: Cross-Origin WebSocket Connection Rejected');
        return;
      }

      this.clients.add(ws);
      ws.on('close', () => this.clients.delete(ws));
    });
  }

  public start() {
    this.server.listen(this.port, '127.0.0.1', () => {
      console.error(`[MCP-SHIELD] Real-time Dashboard running at http://127.0.0.1:${this.port}`);
    });
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
}
