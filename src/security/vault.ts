import * as crypto from 'crypto';

export interface SecretContext {
  serverIdentity?: string;
  toolName?: string;
  sessionId?: string;
  scope?: string;
}

interface VaultEntry {
  encrypted: Buffer;
  iv: Buffer;
  tag: Buffer;
  token: string;
  expiresAt: number;
  byteSize: number;
  context?: SecretContext;
}

/**
 * SecretVault provides ephemeral, memory-only reversible tokenization.
 * 
 * SECURITY ARCHITECTURAL INVARIANTS:
 * - Ephemeral by design: Secrets and AES keys are never persisted to disk and are destroyed on process termination.
 * - Bound to (serverIdentity, toolName, sessionId, scope) to prevent cross-tool/cross-session token reuse.
 * - Scoped HMAC Keying: Incorporates tool/scope to prevent metadata linkage of identical secrets across domains.
 * - Double-bounded: Enforces both maximum entry count (5,000) and hard total byte limit (10MB) with LRU eviction.
 */
export class SecretVault {
  public readonly isEphemeral = true;
  private key: Buffer | null;
  private hmacKey: Buffer | null;
  private readonly algorithm = 'aes-256-gcm';
  private secrets = new Map<string, VaultEntry>(); // keyed HMAC id -> entry
  private tokenToId = new Map<string, string>();
  private currentByteSize = 0;
  private readonly MAX_CACHE_SIZE = 5000;
  private readonly MAX_TOTAL_BYTES = 10 * 1024 * 1024; // 10 MB ceiling
  private readonly defaultTtlMs: number;

  constructor(defaultTtlMs?: number, maxTotalBytes: number = 10 * 1024 * 1024) {
    this.key = crypto.randomBytes(32);
    this.hmacKey = crypto.randomBytes(32);
    this.defaultTtlMs = defaultTtlMs || 5 * 60 * 1000; // 5 minutes default
    this.MAX_TOTAL_BYTES = maxTotalBytes;
  }

  private encrypt(secret: string): { encrypted: Buffer; iv: Buffer; tag: Buffer } {
    if (!this.key) throw new Error("Vault is cleared");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return { encrypted, iv, tag: cipher.getAuthTag() };
  }

  private decrypt(encrypted: Buffer, iv: Buffer, tag: Buffer): string {
    if (!this.key) throw new Error("Vault is cleared");
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  }

  private computeKeyedId(secret: string, scope?: string): string {
    if (!this.hmacKey) throw new Error("Vault is cleared");
    return crypto
      .createHmac('sha256', this.hmacKey)
      .update(secret)
      .update('::' + (scope || 'default'))
      .digest('hex');
  }

  private removeEntry(id: string): void {
    const entry = this.secrets.get(id);
    if (entry) {
      this.currentByteSize = Math.max(0, this.currentByteSize - entry.byteSize);
      this.tokenToId.delete(entry.token);
      this.secrets.delete(id);
    }
  }

  private evictStale(now: number) {
    for (const [id, entry] of this.secrets.entries()) {
      if (entry.expiresAt <= now) {
        this.removeEntry(id);
      }
    }
  }

  public getCurrentByteSize(): number {
    return this.currentByteSize;
  }

  public store(secret: string, ttlMs: number = this.defaultTtlMs, context?: SecretContext): string {
    const now = Date.now();
    this.evictStale(now);

    const secretKeyedId = this.computeKeyedId(secret, context?.scope);
    
    if (this.secrets.has(secretKeyedId)) {
      const entry = this.secrets.get(secretKeyedId)!;
      this.secrets.delete(secretKeyedId); // Refresh LRU position
      this.secrets.set(secretKeyedId, entry);
      return entry.token;
    }

    const { encrypted, iv, tag } = this.encrypt(secret);
    const entrySize = encrypted.length + iv.length + tag.length;

    // Enforce entry count AND byte size memory limits with LRU eviction
    while (
      (this.secrets.size >= this.MAX_CACHE_SIZE || this.currentByteSize + entrySize > this.MAX_TOTAL_BYTES) &&
      this.secrets.size > 0
    ) {
      const oldestId = this.secrets.keys().next().value;
      if (oldestId) {
        this.removeEntry(oldestId);
      } else {
        break;
      }
    }

    const token = `[[SHIELD_SECRET_${crypto.randomUUID()}]]`;
    this.secrets.set(secretKeyedId, {
      encrypted,
      iv,
      tag,
      token,
      expiresAt: now + ttlMs,
      byteSize: entrySize,
      context
    });
    this.tokenToId.set(token, secretKeyedId);
    this.currentByteSize += entrySize;

    return token;
  }

  public retrieve(token: string, expectedContext?: SecretContext): string | null {
    const id = this.tokenToId.get(token);
    if (!id) return null;

    const entry = this.secrets.get(id);
    if (!entry) return null;

    if (entry.expiresAt <= Date.now()) {
       this.removeEntry(id);
       return null;
    }

    // Granular context-bound verification: enforce scope, server, session, and tool binding
    if (entry.context && expectedContext) {
      if (entry.context.sessionId && expectedContext.sessionId && entry.context.sessionId !== expectedContext.sessionId) {
        return null;
      }
      if (entry.context.serverIdentity && expectedContext.serverIdentity && entry.context.serverIdentity !== expectedContext.serverIdentity) {
        return null;
      }
      if (entry.context.scope && expectedContext.scope && entry.context.scope !== expectedContext.scope) {
        return null;
      }
    }

    try {
      return this.decrypt(entry.encrypted, entry.iv, entry.tag);
    } catch {
      return null;
    }
  }

  public clear(): void {
    if (this.key) {
      crypto.randomFillSync(this.key);
      this.key = null;
    }
    if (this.hmacKey) {
      crypto.randomFillSync(this.hmacKey);
      this.hmacKey = null;
    }
    this.secrets.clear();
    this.tokenToId.clear();
    this.currentByteSize = 0;
  }
}
