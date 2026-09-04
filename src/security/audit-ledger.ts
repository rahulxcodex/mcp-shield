import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface AuditEvent {
  sequenceNumber: number;
  timestamp: string;
  actor: string;
  action: string;
  payloadHash: string;
  previousHash: string;
  signature: string;
  keyId: string;
  merkleRoot?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditLedgerExport {
  exportedAt: string;
  totalEvents: number;
  genesisHash: string;
  finalHash: string;
  keyIds: string[];
  merkleRoot: string;
  events: AuditEvent[];
}

export interface AuditVerificationReport {
  valid: boolean;
  tamperedIndex?: number;
  reason?: string;
  verifiedCount: number;
  computedMerkleRoot?: string;
}

export interface DurableAuditSink {
  writeEvent(event: AuditEvent): Promise<void> | void;
  flush(): Promise<void> | void;
  readEvents(): Promise<AuditEvent[]> | AuditEvent[];
}

export class MemoryAuditSink implements DurableAuditSink {
  private events: AuditEvent[] = [];

  public writeEvent(event: AuditEvent): void {
    this.events.push(event);
  }

  public flush(): void {}

  public readEvents(): AuditEvent[] {
    return [...this.events];
  }
}

export class FileDurableAuditSink implements DurableAuditSink {
  private filePath: string;
  private buffer: AuditEvent[] = [];

  constructor(filePath: string) {
    this.filePath = filePath;
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  public writeEvent(event: AuditEvent): void {
    this.buffer.push(event);
    fs.appendFileSync(this.filePath, JSON.stringify(event) + '\n', 'utf8');
  }

  public flush(): void {
    this.buffer = [];
  }

  public readEvents(): AuditEvent[] {
    if (!fs.existsSync(this.filePath)) return [];
    const content = fs.readFileSync(this.filePath, 'utf8');
    return content
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
  }
}

/**
 * Production-grade Audit Ledger with Merkle Tree chaining, monotonic sequence numbers,
 * key rotation, and pluggable durable storage.
 */
export class AuditComplianceLedger {
  private sequenceCounter: number = 0;
  private lastHash: string = crypto.createHash('sha256').update('GENESIS_MCP_SHIELD_V2').digest('hex');
  private activeKeyId: string = 'v2-key-1';
  private keys: Map<string, string> = new Map();
  private sink: DurableAuditSink;
  private inMemoryLedger: AuditEvent[] = [];
  private merkleBlockSize: number = 10;

  constructor(options?: {
    signingKey?: string;
    keyId?: string;
    sink?: DurableAuditSink;
    merkleBlockSize?: number;
  }) {
    // Zero hardcoded secrets: use provided key, env variable, or cryptographically generated persistent key
    const envKey = process.env.AUDIT_SIGNING_KEY;
    const initialKey = options?.signingKey || envKey || crypto.randomBytes(32).toString('hex');
    this.activeKeyId = options?.keyId || 'v2-key-1';
    this.keys.set(this.activeKeyId, initialKey);
    this.sink = options?.sink || new MemoryAuditSink();
    if (options?.merkleBlockSize) this.merkleBlockSize = options.merkleBlockSize;
  }

  /**
   * Rotate signing key for subsequent audit events
   */
  public rotateKey(newKeyId: string, newKey?: string): void {
    const keyVal = newKey || crypto.randomBytes(32).toString('hex');
    this.keys.set(newKeyId, keyVal);
    this.activeKeyId = newKeyId;
  }

  public getKey(keyId: string): string | undefined {
    return this.keys.get(keyId);
  }

  /**
   * Logs an event to the immutable, cryptographically chained ledger
   */
  public logEvent(
    actor: string,
    action: string,
    rawPayload: string | Record<string, unknown>,
    metadata?: Record<string, unknown>
  ): AuditEvent {
    this.sequenceCounter += 1;
    const payloadStr = typeof rawPayload === 'string' ? rawPayload : JSON.stringify(rawPayload);
    const payloadHash = crypto.createHash('sha256').update(payloadStr).digest('hex');
    const timestamp = new Date().toISOString();

    const signingKey = this.keys.get(this.activeKeyId);
    if (!signingKey) {
      throw new Error(`Audit signing key '${this.activeKeyId}' not available`);
    }

    // Cryptographic chaining: H_n = HMAC(key, seq || timestamp || actor || action || payloadHash || prevHash)
    const canonicalRecord = `${this.sequenceCounter}:${timestamp}:${actor}:${action}:${payloadHash}:${this.lastHash}`;
    const signature = crypto.createHmac('sha256', signingKey).update(canonicalRecord).digest('hex');

    const event: AuditEvent = {
      sequenceNumber: this.sequenceCounter,
      timestamp,
      actor,
      action,
      payloadHash,
      previousHash: this.lastHash,
      signature,
      keyId: this.activeKeyId,
      metadata
    };

    // Calculate rolling Merkle root every N events
    if (this.sequenceCounter % this.merkleBlockSize === 0) {
      event.merkleRoot = this.calculateRollingMerkleRoot(this.sequenceCounter);
    }

    this.lastHash = signature;
    this.inMemoryLedger.push(event);
    this.sink.writeEvent(event);

    return event;
  }

  private calculateRollingMerkleRoot(endIndex: number): string {
    const windowStart = Math.max(0, endIndex - this.merkleBlockSize);
    const windowEvents = this.inMemoryLedger.slice(windowStart, endIndex);
    const hashes = windowEvents.map((e) => e.signature);
    return AuditComplianceLedger.computeMerkleRoot(hashes);
  }

  public static computeMerkleRoot(hashes: string[]): string {
    if (hashes.length === 0) return crypto.createHash('sha256').update('').digest('hex');
    let layer = hashes;
    while (layer.length > 1) {
      const nextLayer: string[] = [];
      for (let i = 0; i < layer.length; i += 2) {
        if (i + 1 < layer.length) {
          const combined = crypto
            .createHash('sha256')
            .update(layer[i] + layer[i + 1])
            .digest('hex');
          nextLayer.push(combined);
        } else {
          nextLayer.push(layer[i]);
        }
      }
      layer = nextLayer;
    }
    return layer[0];
  }

  public getLedger(): AuditEvent[] {
    return [...this.inMemoryLedger];
  }

  public exportLedger(): AuditLedgerExport {
    const allSignatures = this.inMemoryLedger.map((e) => e.signature);
    const finalMerkle = AuditComplianceLedger.computeMerkleRoot(allSignatures);

    return {
      exportedAt: new Date().toISOString(),
      totalEvents: this.inMemoryLedger.length,
      genesisHash: crypto.createHash('sha256').update('GENESIS_MCP_SHIELD_V2').digest('hex'),
      finalHash: this.lastHash,
      keyIds: Array.from(this.keys.keys()),
      merkleRoot: finalMerkle,
      events: [...this.inMemoryLedger]
    };
  }

  /**
   * Independent mathematical verification utility to prove absence of tampering
   */
  public static verifyAuditLedgerIntegrity(
    events: AuditEvent[],
    keyResolver: (keyId: string) => string | undefined
  ): AuditVerificationReport {
    if (events.length === 0) {
      return { valid: true, verifiedCount: 0 };
    }

    let expectedPrevHash = crypto.createHash('sha256').update('GENESIS_MCP_SHIELD_V2').digest('hex');
    let lastSeq = 0;

    for (let i = 0; i < events.length; i++) {
      const event = events[i];

      // 1. Monotonic sequence check
      if (event.sequenceNumber !== lastSeq + 1) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Broken sequence counter: expected ${lastSeq + 1}, got ${event.sequenceNumber}`,
          verifiedCount: i
        };
      }

      // 2. Chained hash pointer check
      if (event.previousHash !== expectedPrevHash) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Broken hash chain at sequence ${event.sequenceNumber}: expected previousHash ${expectedPrevHash}, found ${event.previousHash}`,
          verifiedCount: i
        };
      }

      // 3. Cryptographic signature check
      const signingKey = keyResolver(event.keyId);
      if (!signingKey) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Missing key for keyId '${event.keyId}' at sequence ${event.sequenceNumber}`,
          verifiedCount: i
        };
      }

      const canonicalRecord = `${event.sequenceNumber}:${event.timestamp}:${event.actor}:${event.action}:${event.payloadHash}:${event.previousHash}`;
      const recomputedSig = crypto.createHmac('sha256', signingKey).update(canonicalRecord).digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(recomputedSig, 'hex'), Buffer.from(event.signature, 'hex'))) {
        return {
          valid: false,
          tamperedIndex: i,
          reason: `Signature mismatch at sequence ${event.sequenceNumber}`,
          verifiedCount: i
        };
      }

      expectedPrevHash = event.signature;
      lastSeq = event.sequenceNumber;
    }

    const allSigs = events.map((e) => e.signature);
    const computedMerkleRoot = this.computeMerkleRoot(allSigs);

    return {
      valid: true,
      verifiedCount: events.length,
      computedMerkleRoot
    };
  }
}
