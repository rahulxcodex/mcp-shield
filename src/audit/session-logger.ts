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

  private canonicalStringify(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => this.canonicalStringify(item)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const result: string[] = [];
    for (const key of sortedKeys) {
      result.push(JSON.stringify(key) + ':' + this.canonicalStringify(obj[key]));
    }
    return '{' + result.join(',') + '}';
  }

  public log(event: { type: string; toolName?: string; action?: string; ruleId?: string; payload?: any; reason?: string }) {
    const eventObj = { timestamp: new Date().toISOString(), ...event };
    const canonicalData = this.canonicalStringify(eventObj);
    
    // Hash chain for tamper-evidence
    const hash = crypto.createHash('sha256').update(this.previousHash + canonicalData).digest('hex');
    const entry = { data: eventObj, hash, previousHash: this.previousHash };
    
    this.previousHash = hash;
    fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n');
  }
}
