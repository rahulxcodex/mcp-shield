import * as fs from 'fs';
import * as crypto from 'crypto';

export class ReplayCommand {
  private static canonicalStringify(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => ReplayCommand.canonicalStringify(item)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const result: string[] = [];
    for (const key of sortedKeys) {
      result.push(JSON.stringify(key) + ':' + ReplayCommand.canonicalStringify(obj[key]));
    }
    return '{' + result.join(',') + '}';
  }

  public static run(logPath: string) {
    if (!logPath) {
      console.error('Usage: mcp-shield replay <path-to-session.jsonl>');
      process.exit(1);
    }
    if (!fs.existsSync(logPath)) {
      console.error(`Log file not found: ${logPath}`);
      process.exit(1);
    }
    
    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    let prevHash = 'GENESIS';
    let expectedSeq = 0;
    const auditKey = process.env.MCP_SHIELD_AUDIT_KEY || null;
    
    console.log(`\n▶️  REPLAYING SESSION: ${logPath}\n`);
    
    for (const line of lines) {
       if (!line.trim()) continue;
       const entry = JSON.parse(line);
       
       // Verify sequence order to prevent truncation or reordering
       if (entry.seq !== undefined && entry.seq !== expectedSeq) {
          console.error(`❌ SEQUENCE MISMATCH! Expected seq #${expectedSeq}, got #${entry.seq}`);
          process.exit(1);
       }
       expectedSeq++;

       // Verify integrity using canonical JSON serialization
       const canonicalData = ReplayCommand.canonicalStringify(entry.data);
       let computedHash: string;
       if (auditKey) {
         computedHash = crypto.createHmac('sha256', auditKey).update(prevHash + canonicalData).digest('hex');
       } else {
         computedHash = crypto.createHash('sha256').update(prevHash + canonicalData).digest('hex');
       }
       
       if (computedHash !== entry.hash || prevHash !== entry.previousHash) {
          console.error(`❌ TAMPER DETECTED! Hash chain broken at seq #${entry.seq ?? 'N/A'} timestamp ${entry.data.timestamp}`);
          process.exit(1);
       }
       prevHash = entry.hash;

       // Visualize
       console.log(`[#${entry.seq ?? 0} | ${entry.data.timestamp}] ${entry.data.type.toUpperCase()}`);
       if (entry.data.toolName) console.log(`  Tool: ${entry.data.toolName}`);
       if (entry.data.action) console.log(`  Action: ${entry.data.action}`);
       if (entry.data.reason) console.log(`  Reason: ${entry.data.reason}`);
       console.log('---');
    }
    console.log(`\n✅ Session Replay Complete. Total ${expectedSeq} log entries mathematically verified.`);
  }
}
