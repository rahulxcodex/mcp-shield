import crypto from 'crypto';

export interface GeneratedApiKey {
  keyId: string;
  name: string;
  keyPrefix: string;
  rawKey: string;
  keyHash: string;
  createdAt: string;
  expiresAt: string | null;
  seats: number;
}

/**
 * Computes SHA-256 hash of an API key secret.
 * Raw API keys are NEVER stored in the database.
 */
export function hashApiKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey.trim()).digest('hex');
}

/**
 * Constant-time comparison between raw input key and stored SHA-256 hash.
 * Resists timing side-channel attacks.
 */
export function verifyKeyHash(rawKey: string, storedHash: string): boolean {
  if (!rawKey || !storedHash) return false;
  const computedHash = hashApiKey(rawKey);
  const bufA = Buffer.from(computedHash, 'hex');
  const bufB = Buffer.from(storedHash, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generates an API key with a unique lookup prefix and cryptographic entropy:
 * Format: mcp_live_<8_char_prefix>_<32_char_random_entropy>
 */
export function generateApiKey(options: {
  name?: string;
  clientType?: string;
  expiresInDays?: number;
  seats?: number;
}): GeneratedApiKey {
  const prefixId = crypto.randomBytes(4).toString('hex');
  const keyPrefix = `mcp_live_${prefixId}`;
  const secretEntropy = crypto.randomBytes(16).toString('hex');
  const rawKey = `${keyPrefix}_${secretEntropy}`;
  const keyHash = hashApiKey(rawKey);
  const now = new Date().toISOString();

  const days = options.expiresInDays && options.expiresInDays > 0 ? options.expiresInDays : null;
  const expiresAt = days ? new Date(Date.now() + days * 24 * 3600 * 1000).toISOString() : null;

  const displayName = options.name?.trim() || `Production MCP Key (${options.clientType || 'Gateway'})`;

  return {
    keyId: `key-${Date.now()}-${prefixId}`,
    name: displayName,
    keyPrefix,
    rawKey,
    keyHash,
    createdAt: now,
    expiresAt,
    seats: options.seats || 25,
  };
}

/**
 * Extracts canonical lookup prefix from API key string.
 */
export function extractKeyPrefix(key: string): string {
  if (!key) return '';
  const trimmed = key.trim();
  const match = trimmed.match(/^(mcp_live(?:_sec)?_[a-f0-9]{8})_[a-f0-9]{32}$/i);
  if (match) {
    return match[1];
  }
  const prefixMatch = trimmed.match(/^(mcp_live(?:_sec)?_[a-f0-9]{8})/i);
  if (prefixMatch) {
    return prefixMatch[1];
  }
  return trimmed.substring(0, Math.min(trimmed.length, 20));
}

/**
 * Validates cryptographic structure and entropy format of an API key.
 */
export function validateApiKeyStructure(key: string): boolean {
  if (!key) return false;
  return /^(mcp_live(?:_sec)?_[a-f0-9]{8})_[a-f0-9]{32}$/i.test(key.trim());
}

/**
 * Parses an API key into its canonical prefix and secret entropy components.
 */
export function parseApiKey(key: string): { prefix: string; secret: string; isValid: boolean } {
  const isValid = validateApiKeyStructure(key);
  const prefix = extractKeyPrefix(key);
  const parts = key.trim().split('_');
  const secret = parts[parts.length - 1] || '';
  return { prefix, secret, isValid };
}

