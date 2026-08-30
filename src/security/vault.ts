import * as crypto from 'crypto';

export class SecretVault {
  private key: Buffer;
  private readonly algorithm = 'aes-256-gcm';
  private secrets = new Map<string, { encrypted: Buffer; iv: Buffer; tag: Buffer }>();
  private tokenToId = new Map<string, string>();
  private idToToken = new Map<string, string>();

  // Ring buffer for eviction
  private readonly MAX_CACHE_SIZE = 5000;
  private evictionRing = new Array<string>(5000);
  private ringIndex = 0;
  private currentSize = 0;

  constructor() {
    // Generate a fresh session-scoped encryption key
    this.key = crypto.randomBytes(32);
  }

  private encrypt(secret: string): { encrypted: Buffer; iv: Buffer; tag: Buffer } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return { encrypted, iv, tag: cipher.getAuthTag() };
  }

  private decrypt(encrypted: Buffer, iv: Buffer, tag: Buffer): string {
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  }

  public store(secret: string): string {
    // Check if we already have it (we hash the secret to check without keeping plaintext in memory)
    const secretHash = crypto.createHash('sha256').update(secret).digest('hex');
    
    if (this.idToToken.has(secretHash)) {
      return this.idToToken.get(secretHash)!;
    }

    if (this.currentSize >= this.MAX_CACHE_SIZE) {
      const oldestId = this.evictionRing[this.ringIndex];
      const oldToken = this.idToToken.get(oldestId)!;
      this.secrets.delete(oldestId);
      this.idToToken.delete(oldestId);
      this.tokenToId.delete(oldToken);
    } else {
      this.currentSize++;
    }

    const token = `[[SHIELD_SECRET_${crypto.randomUUID()}]]`;
    const encryptedData = this.encrypt(secret);
    
    this.secrets.set(secretHash, encryptedData);
    this.idToToken.set(secretHash, token);
    this.tokenToId.set(token, secretHash);

    this.evictionRing[this.ringIndex] = secretHash;
    this.ringIndex = (this.ringIndex + 1) % this.MAX_CACHE_SIZE;

    return token;
  }

  public retrieve(token: string): string | null {
    const id = this.tokenToId.get(token);
    if (!id) return null;

    const data = this.secrets.get(id);
    if (!data) return null;

    try {
      return this.decrypt(data.encrypted, data.iv, data.tag);
    } catch {
      return null;
    }
  }
}
