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
              
              div.innerHTML = \`<span style="color: \${color}">[\${data.timestamp}] \${data.type.toUpperCase()}</span> \${data.toolName ? 'Tool: ' + data.toolName : ''} \${data.reason ? '<br/>Reason: ' + data.reason : ''}\`;
              logs.prepend(div);
            };
          </script>
        </body>
        </html>
      `);
    });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      ws.on('close', () => this.clients.delete(ws));
    });
  }

  public start() {
    this.server.listen(this.port, () => {
      console.error(`[MCP-SHIELD] Real-time Dashboard running at http://localhost:${this.port}`);
    });
  }

  public broadcast(event: any) {
    const payload = { timestamp: new Date().toISOString(), ...event };
    const message = JSON.stringify(payload);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  }
}
