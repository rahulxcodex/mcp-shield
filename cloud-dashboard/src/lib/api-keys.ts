import * as crypto from 'crypto';
import { SupabaseClient } from '@supabase/supabase-js';

export interface GeneratedKeyResult {
  rawKey: string;
  keyPrefix: string;
  keyHash: string;
}

export interface ApiKeyRecord {
  id: string;
  project_id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  expires_at?: string;
  revoked: boolean;
}

export function generateSecureApiKey(): GeneratedKeyResult {
  const entropy = crypto.randomBytes(32).toString('hex');
  const rawKey = `mcp_live_${entropy}`;
  const keyPrefix = rawKey.substring(0, 17); // e.g. "mcp_live_a1b2c3d4"
  const keyHash = hashApiKey(rawKey);

  return {
    rawKey,
    keyPrefix,
    keyHash,
  };
}

export function hashApiKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey.trim()).digest('hex');
}

export function verifyApiKeyHash(rawKey: string, storedHash: string): boolean {
  try {
    const computedHash = hashApiKey(rawKey);
    const bufA = Buffer.from(computedHash, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== 32 || bufB.length !== 32) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

export const verifyKeyHash = verifyApiKeyHash;

/**
 * Derives a distinct, high-entropy HMAC secret for telemetry signing from raw API key.
 * Keeps stored database verifier (SHA-256 key_hash) separated from HMAC key material (SEC-FINDING-003).
 */
export function deriveTelemetryHmacSecret(rawKey: string): string {
  const cleanKey = rawKey.trim();
  const salt = Buffer.from('mcp-shield-telemetry-salt-v1', 'utf8');
  const info = Buffer.from('mcp-shield-telemetry-hmac', 'utf8');
  const derived = crypto.hkdfSync('sha256', Buffer.from(cleanKey, 'utf8'), salt, info, 32);
  return Buffer.from(derived).toString('hex');
}

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

export function validateApiKeyStructure(key: string): boolean {
  if (!key) return false;
  return /^(mcp_live(?:_sec)?_[a-f0-9]{8})_[a-f0-9]{32}$/i.test(key.trim());
}

export function parseApiKey(key: string): { prefix: string; secret: string; isValid: boolean } {
  const isValid = validateApiKeyStructure(key);
  const prefix = extractKeyPrefix(key);
  const parts = key.trim().split('_');
  const secret = parts[parts.length - 1] || '';
  return { prefix, secret, isValid };
}

export async function createProjectApiKey(
  supabaseAdmin: SupabaseClient,
  projectId: string,
  keyName = 'Default API Key'
): Promise<{ rawKey: string; keyRecord: Partial<ApiKeyRecord> }> {
  // 1. Single Active Key Policy: rotate/revoke any existing active keys for this project
  await supabaseAdmin
    .from('api_keys')
    .update({
      status: 'revoked',
      revoked: true,
      expires_at: '1970-01-01T00:00:00.000Z',
      revocation_reason: 'Rotated by Single Active Key Policy'
    })
    .eq('project_id', projectId)
    .eq('revoked', false);

  // 2. Generate new cryptographic key pair (secret + SHA-256 verifier)
  const { rawKey, keyPrefix, keyHash } = generateSecureApiKey();

  // 3. Store ONLY the verifier hash, NEVER the plaintext key
  const { data: newKey, error } = await supabaseAdmin
    .from('api_keys')
    .insert([
      {
        project_id: projectId,
        name: keyName,
        key_prefix: keyPrefix,
        key_hash: keyHash, // Storing cryptographic verifier
        status: 'active',
        revoked: false,
      },
    ])
    .select('id, project_id, name, key_prefix, created_at, revoked')
    .single();

  if (error || !newKey) {
    throw new Error(error ? `Failed to store API key: ${error.message}` : 'Failed to create key');
  }

  return {
    rawKey, // Returned ONLY ONCE to the creator
    keyRecord: newKey,
  };
}

export async function resolveProjectFromApiKey(
  supabaseAdmin: SupabaseClient,
  rawApiKey: string
): Promise<{ valid: boolean; projectId?: string; organizationId?: string; error?: string }> {
  if (!rawApiKey) {
    return { valid: false, error: 'Missing API key' };
  }

  const trimmed = rawApiKey.trim();
  if (trimmed.length <= 24) {
    return { valid: false, error: 'Authentication failed: Full API key required; prefix-only authentication is prohibited' };
  }

  const prefix = trimmed.substring(0, 17);

  // Index-based lookup by key_prefix
  const { data: records, error } = await supabaseAdmin
    .from('api_keys')
    .select('id, organization_id, project_id, key_hash, revoked, expires_at')
    .eq('key_prefix', prefix);

  if (error || !records || records.length === 0) {
    return { valid: false, error: 'Invalid API key or key not found' };
  }

  // Verify against candidate records using constant-time comparison
  for (const rec of records) {
    if (rec.revoked) continue;
    if (rec.expires_at && new Date(rec.expires_at).getTime() < Date.now()) continue;

    if (verifyApiKeyHash(trimmed, rec.key_hash)) {
      return { valid: true, projectId: rec.project_id, organizationId: rec.organization_id };
    }
  }

  return { valid: false, error: 'Authentication failed: Invalid key verifier or key expired' };
}
