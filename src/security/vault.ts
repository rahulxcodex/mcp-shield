import * as crypto from 'crypto';

interface VaultEntry {
  encrypted: Buffer;
  iv: Buffer;
  tag: Buffer;
  token: string;
  expiresAt: number;
}

export class SecretVault {
  private key: Buffer | null;
  private hmacKey: Buffer | null;
  private readonly algorithm = 'aes-256-gcm';
  private secrets = new Map<string, VaultEntry>(); // keyed HMAC id -> entry
  private tokenToId = new Map<string, string>();
  private readonly MAX_CACHE_SIZE = 5000;
  private readonly DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour

  constructor() {
    this.key = crypto.randomBytes(32);
    this.hmacKey = crypto.randomBytes(32);
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

  private computeKeyedId(secret: string): string {
    if (!this.hmacKey) throw new Error("Vault is cleared");
    return crypto.createHmac('sha256', this.hmacKey).update(secret).digest('hex');
  }

  private evictStale(now: number) {
    for (const [id, entry] of this.secrets.entries()) {
      if (entry.expiresAt <= now) {
        this.tokenToId.delete(entry.token);
        this.secrets.delete(id);
      }
    }
  }

  public store(secret: string, ttlMs: number = this.DEFAULT_TTL_MS): string {
    const now = Date.now();
    this.evictStale(now);

    const secretKeyedId = this.computeKeyedId(secret);
    
    if (this.secrets.has(secretKeyedId)) {
      const entry = this.secrets.get(secretKeyedId)!;
      this.secrets.delete(secretKeyedId); // Refresh LRU position
      this.secrets.set(secretKeyedId, entry);
      return entry.token;
    }

    if (this.secrets.size >= this.MAX_CACHE_SIZE) {
      const oldestId = this.secrets.keys().next().value;
      if (oldestId) {
        const oldestEntry = this.secrets.get(oldestId)!;
        this.tokenToId.delete(oldestEntry.token);
        this.secrets.delete(oldestId);
      }
    }

    const token = `[[SHIELD_SECRET_${crypto.randomUUID()}]]`;
    const { encrypted, iv, tag } = this.encrypt(secret);
    
    this.secrets.set(secretKeyedId, { encrypted, iv, tag, token, expiresAt: now + ttlMs });
    this.tokenToId.set(token, secretKeyedId);

    return token;
  }

  public retrieve(token: string): string | null {
    const id = this.tokenToId.get(token);
    if (!id) return null;

    const entry = this.secrets.get(id);
    if (!entry) return null;

    if (entry.expiresAt <= Date.now()) {
       this.secrets.delete(id);
       this.tokenToId.delete(token);
       return null;
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
  }
}
