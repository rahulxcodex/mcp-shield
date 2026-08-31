import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

export class SessionLogger {
  private logFile: string;
  private previousHash: string = 'GENESIS';
  private sequenceNumber: number = 0;
  private auditKey: string | null = process.env.MCP_SHIELD_AUDIT_KEY || null;

  private config?: any;

  constructor(customLogFile?: string, config?: any) {
    this.config = config;
    if (customLogFile) {
      this.logFile = customLogFile;
    } else {
      const logDir = this.config?.logDir || path.join(process.cwd(), '.mcp-shield', 'logs');
      fs.mkdirSync(logDir, { recursive: true });
      this.logFile = path.join(logDir, `session-${Date.now()}.jsonl`);
    }
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
      if (obj[key] !== undefined) {
        result.push(JSON.stringify(key) + ':' + this.canonicalStringify(obj[key]));
      }
    }
    return '{' + result.join(',') + '}';
  }

  private computeDigest(data: string): string {
    const tamperEvident = this.config?.tamperEvidentHashing !== false; // Default true
    if (!tamperEvident) {
       return 'DISABLED';
    }
    if (this.auditKey) {
      return crypto.createHmac('sha256', this.auditKey).update(data).digest('hex');
    }
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  public startSession(configSnapshot: any, registeredTools: string[]) {
    this.log({
      type: 'SESSION_START',
      payload: {
        config: configSnapshot,
        tools: registeredTools,
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch
        }
      }
    });
  }

  public endSession() {
    this.log({ type: 'SESSION_END' });
  }

  private sanitizePayloadForAudit(payload: any): any {
    if (!payload || typeof payload !== 'object') return payload;
    const sanitized: Record<string, any> = Array.isArray(payload) ? [] : {};
    for (const [k, v] of Object.entries(payload)) {
      if (typeof v === 'string') {
        if (v.length > 512) {
          sanitized[k] = {
            type: 'string',
            byteLength: Buffer.byteLength(v, 'utf8'),
            sha256: crypto.createHash('sha256').update(v).digest('hex'),
            excerpt: v.slice(0, 128) + '...[truncated for audit data minimization]'
          };
        } else {
          sanitized[k] = v;
        }
      } else if (typeof v === 'object' && v !== null) {
        sanitized[k] = this.sanitizePayloadForAudit(v);
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  }

  public log(event: { type: string; toolName?: string; action?: string; ruleId?: string; payload?: any; reason?: string }) {
    if (this.config?.enabled === false) return; // Skip if disabled

    const seq = this.sequenceNumber++;
    const safePayload = event.payload ? this.sanitizePayloadForAudit(event.payload) : undefined;
    const eventObj = { seq, timestamp: new Date().toISOString(), ...event, ...(safePayload ? { payload: safePayload } : {}) };
    const canonicalData = this.canonicalStringify(eventObj);
    
    // Hash chain with sequence for tamper-evidence & anti-truncation
    const hash = this.computeDigest(this.previousHash + canonicalData);
    const entry = { seq, data: eventObj, hash, previousHash: this.previousHash };
    
    this.previousHash = hash;
    const logString = JSON.stringify(entry);
    fs.appendFileSync(this.logFile, logString + '\n');
    
    if (this.config?.remoteSinkUrl) {
      this.sendToRemoteSink(logString);
    }
  }

  private sendToRemoteSink(payload: string) {
    try {
      const parsedUrl = new URL(this.config.remoteSinkUrl);
      const reqModule = parsedUrl.protocol === 'https:' ? https : http;
      const req = reqModule.request({
        method: 'POST',
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.pathname + parsedUrl.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      });
      req.on('error', (err) => console.error('[MCP-SHIELD] Remote audit sink error:', err));
      req.write(payload);
      req.end();
    } catch (e) {
      console.error('[MCP-SHIELD] Failed to parse or send to remoteSinkUrl', e);
    }
  }
}
