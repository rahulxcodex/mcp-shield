import * as fs from 'fs';
import * as crypto from 'crypto';

export class ReplayCommand {
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
    
    console.log(`\n▶️  REPLAYING SESSION: ${logPath}\n`);
    
    for (const line of lines) {
       if (!line.trim()) continue;
       const entry = JSON.parse(line);
       
       // Verify integrity
       const rawData = JSON.stringify(entry.data);
       const computedHash = crypto.createHash('sha256').update(prevHash + rawData).digest('hex');
       
       if (computedHash !== entry.hash || prevHash !== entry.previousHash) {
          console.error(`❌ TAMPER DETECTED! Hash chain broken at timestamp ${entry.data.timestamp}`);
          process.exit(1);
       }
       prevHash = entry.hash;

       // Visualize
       console.log(`[${entry.data.timestamp}] ${entry.data.type.toUpperCase()}`);
       if (entry.data.toolName) console.log(`  Tool: ${entry.data.toolName}`);
       if (entry.data.action) console.log(`  Action: ${entry.data.action}`);
       if (entry.data.reason) console.log(`  Reason: ${entry.data.reason}`);
       console.log('---');
    }
    console.log(`\n✅ Session Replay Complete. Log integrity mathematically verified.`);
  }
}
