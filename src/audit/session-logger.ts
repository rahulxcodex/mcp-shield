import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export class SessionLogger {
  private logFile: string;
  private previousHash: string = 'GENESIS';

  constructor() {
    const logDir = path.join(process.cwd(), '.mcp-shield', 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    this.logFile = path.join(logDir, `session-${Date.now()}.jsonl`);
  }

  public log(event: { type: string; toolName?: string; action?: string; ruleId?: string; payload?: any; reason?: string }) {
    const rawData = JSON.stringify({ timestamp: new Date().toISOString(), ...event });
    
    // Hash chain for tamper-evidence
    const hash = crypto.createHash('sha256').update(this.previousHash + rawData).digest('hex');
    const entry = { data: JSON.parse(rawData), hash, previousHash: this.previousHash };
    
    this.previousHash = hash;
    fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n');
  }
}
