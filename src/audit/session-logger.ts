import * as fs from 'fs';
import * as path from 'path';

export class SessionLogger {
  private logFile: string;

  constructor() {
    const logDir = path.join(process.cwd(), '.mcp-shield', 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    this.logFile = path.join(logDir, `session-${Date.now()}.jsonl`);
  }

  public log(event: { type: string; toolName?: string; action?: string; ruleId?: string; payload?: any; reason?: string }) {
    const entry = {
      timestamp: new Date().toISOString(),
      ...event
    };
    fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n');
  }
}
