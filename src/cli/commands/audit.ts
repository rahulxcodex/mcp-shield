import * as fs from 'fs';
import * as path from 'path';
import { AuditComplianceLedger, AuditEvent, AuditLedgerExport } from '../../security/audit-ledger';

export class AuditCommand {
  public static resolveLogFile(customPath?: string): string {
    if (customPath && fs.existsSync(customPath)) {
      return customPath;
    }
    const candidates = [
      customPath,
      path.join(process.cwd(), '.mcp-shield', 'audit.log'),
      path.join(process.cwd(), 'audit.log'),
      path.join(process.cwd(), 'logs', 'audit.log'),
    ].filter(Boolean) as string[];

    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return candidates[0] || path.join(process.cwd(), '.mcp-shield', 'audit.log');
  }

  public static loadEvents(logFile: string): AuditEvent[] {
    if (!fs.existsSync(logFile)) {
      return [];
    }
    const content = fs.readFileSync(logFile, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim().length > 0);
    const events: AuditEvent[] = [];

    for (let i = 0; i < lines.length; i++) {
      try {
        const parsed = JSON.parse(lines[i]);
        if (parsed.sequenceNumber !== undefined && parsed.signature) {
          events.push(parsed as AuditEvent);
        } else {
          // Normalize standard proxy event to AuditEvent shape if needed
          events.push({
            sequenceNumber: i + 1,
            timestamp: parsed.timestamp || new Date().toISOString(),
            actor: parsed.actor || parsed.clientName || 'mcp-agent',
            action: parsed.action || parsed.type || 'EXECUTE',
            payloadHash: parsed.payloadHash || parsed.hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            previousHash: parsed.previousHash || '0000000000000000000000000000000000000000000000000000000000000000',
            signature: parsed.signature || 'sig_mock_audit_signature_placeholder',
            keyId: parsed.keyId || 'default-audit-key',
            metadata: parsed
          });
        }
      } catch {}
    }
    return events;
  }

  public static run(args: string[] = []): void {
    const subcmd = args[0] || 'help';

    if (subcmd === 'export') {
      let format = 'cef';
      let outFile: string | null = null;
      let logFileArg: string | null = null;

      for (let i = 1; i < args.length; i++) {
        if (args[i].startsWith('--format=')) {
          format = args[i].split('=')[1].toLowerCase();
        } else if (args[i] === '--format' && args[i + 1]) {
          format = args[i + 1].toLowerCase();
          i++;
        } else if (args[i].startsWith('--out=')) {
          outFile = args[i].split('=')[1];
        } else if (args[i] === '--out' && args[i + 1]) {
          outFile = args[i + 1];
          i++;
        } else if (!args[i].startsWith('--')) {
          logFileArg = args[i];
        }
      }

      const logFile = AuditCommand.resolveLogFile(logFileArg || undefined);
      const events = AuditCommand.loadEvents(logFile);
      const allSignatures = events.map((e) => e.signature);
      const merkleRoot = AuditComplianceLedger.computeMerkleRoot(allSignatures);

      const exportData: AuditLedgerExport = {
        exportedAt: new Date().toISOString(),
        totalEvents: events.length,
        genesisHash: '0000000000000000000000000000000000000000000000000000000000000000',
        finalHash: events.length > 0 ? events[events.length - 1].signature : '0000000000000000000000000000000000000000000000000000000000000000',
        keyIds: Array.from(new Set(events.map((e) => e.keyId))),
        merkleRoot,
        events
      };

      let output = '';
      if (format === 'cef') {
        output = AuditComplianceLedger.exportToCef(exportData);
      } else if (format === 'syslog') {
        output = AuditComplianceLedger.exportToSyslog(exportData);
      } else {
        output = JSON.stringify(exportData, null, 2);
      }

      if (outFile) {
        fs.writeFileSync(outFile, output, 'utf8');
        console.log(`[MCP-SHIELD AUDIT] Exported ${events.length} audit events in ${format.toUpperCase()} format to ${outFile}`);
      } else {
        console.log(output);
      }
    } else if (subcmd === 'verify') {
      const logFile = AuditCommand.resolveLogFile(args[1]);
      const events = AuditCommand.loadEvents(logFile);

      if (events.length === 0) {
        console.log('[MCP-SHIELD AUDIT] No audit log events found to verify.');
        return;
      }

      const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(events, (keyId) => {
        return process.env.MCP_SHIELD_AUDIT_KEY || 'default-audit-key';
      });

      if (report.valid) {
        console.log(`\x1b[32m[MCP-SHIELD AUDIT] SUCCESS: Verified ${report.verifiedCount} audit events. Merkle Root: ${report.computedMerkleRoot}\x1b[0m`);
      } else {
        console.error(`\x1b[31m[MCP-SHIELD AUDIT] FAILED: Tampering detected at index ${report.tamperedIndex}: ${report.reason}\x1b[0m`);
        if (process.env.NODE_ENV !== 'test') process.exit(1);
      }
    } else {
      console.log([
        '🛡️  MCP-SHIELD AUDIT',
        'Usage:',
        '  mcp-shield audit export [--format=cef|jsonl|syslog] [--out=<file>] [log_file]',
        '  mcp-shield audit verify [log_file]'
      ].join('\n'));
    }
  }
}
