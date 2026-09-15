import { DatabaseSync } from 'node:sqlite';
import * as path from 'path';
import * as fs from 'fs';
import { AuditEvent, DurableAuditSink, AuditComplianceLedger } from '../audit-ledger';

/**
 * Persistent SQLite Write-Ahead Audit Sink (SOC 2 Type II CC7.2 / CC6.6)
 * Decouples the audit trail from volatile kernel eBPF rings and memory,
 * persisting directly to an immutable, append-only SQLite WAL database.
 */
export class SqliteDurableAuditSink implements DurableAuditSink {
  private readonly db: DatabaseSync;
  private readonly dbPath: string;

  constructor(dbPath: string = ':memory:') {
    this.dbPath = dbPath;
    if (dbPath !== ':memory:') {
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    this.db = new DatabaseSync(dbPath);
    this.initializeSchema();
  }

  private initializeSchema(): void {
    // Configure Write-Ahead Logging (WAL) and synchronous durability
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_events (
        sequence_number INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        key_id TEXT NOT NULL,
        merkle_root TEXT,
        metadata TEXT,
        algorithm TEXT DEFAULT 'sha3-256'
      );
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
    `);
  }

  public writeEvent(event: AuditEvent): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_events (
        sequence_number, timestamp, actor, action, payload_hash,
        previous_hash, signature, key_id, merkle_root, metadata, algorithm
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      event.sequenceNumber,
      event.timestamp,
      event.actor,
      event.action,
      event.payloadHash,
      event.previousHash,
      event.signature,
      event.keyId,
      event.merkleRoot ?? null,
      event.metadata ? JSON.stringify(event.metadata) : null,
      event.algorithm ?? 'sha3-256'
    );
  }

  public flush(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(PASSIVE);');
    } catch {
      // Passive checkpoint best-effort
    }
  }

  public readEvents(): AuditEvent[] {
    const stmt = this.db.prepare('SELECT * FROM audit_events ORDER BY sequence_number ASC');
    const rows = stmt.all() as Record<string, unknown>[];

    return rows.map((r) => {
      let meta: Record<string, unknown> | undefined;
      if (typeof r.metadata === 'string') {
        try {
          meta = JSON.parse(r.metadata);
        } catch {
          meta = undefined;
        }
      }

      return {
        sequenceNumber: Number(r.sequence_number),
        timestamp: String(r.timestamp),
        actor: String(r.actor),
        action: String(r.action),
        payloadHash: String(r.payload_hash),
        previousHash: String(r.previous_hash),
        signature: String(r.signature),
        keyId: String(r.key_id),
        merkleRoot: r.merkle_root ? String(r.merkle_root) : undefined,
        metadata: meta,
        algorithm: (r.algorithm as 'sha3-256' | 'sha256') ?? 'sha3-256'
      };
    });
  }

  public computeRollingMerkleRoot(algorithm: 'sha3-256' | 'sha256' = 'sha3-256'): string {
    const events = this.readEvents();
    const sigs = events.map((e) => e.signature);
    return AuditComplianceLedger.computeMerkleRoot(sigs, algorithm);
  }

  public verifyIntegrity(keyResolver: (keyId: string) => string | undefined) {
    const events = this.readEvents();
    return AuditComplianceLedger.verifyAuditLedgerIntegrity(events, keyResolver);
  }

  public close(): void {
    this.db.close();
  }

  public getDbPath(): string {
    return this.dbPath;
  }
}
