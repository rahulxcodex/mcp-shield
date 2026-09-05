import { createAdminSupabaseClient } from '@/lib/supabase';
import { jsonSuccess, jsonError } from '@/lib/api-response';
import { z } from 'zod';
import * as crypto from 'crypto';
import { getDistributedStateStore } from '@/lib/distributed-state';
import { deriveTelemetryHmacSecret } from '@/lib/api-keys';

export const runtime = 'nodejs';

// Replay cache to prevent re-submitting identical telemetry batches within the 5-minute window
const recentNonceCache = new Map<string, number>();

// In-memory sliding window rate limiter per project (120 batches per minute)
const telemetryRateLimitMap = new Map<string, number[]>();

function cleanReplayCache(now: number) {
  for (const [nonce, expiresAt] of recentNonceCache.entries()) {
    if (now > expiresAt) {
      recentNonceCache.delete(nonce);
    }
  }
}

// Periodic eviction sweep to prevent memory leak from stale project rate-limit keys (SEC-FINDING-014)
function cleanTelemetryRateLimits(now: number, windowMs: number = 60_000) {
  for (const [projectId, timestamps] of telemetryRateLimitMap.entries()) {
    const active = timestamps.filter(t => t > now - windowMs);
    if (active.length === 0) {
      telemetryRateLimitMap.delete(projectId);
    } else if (active.length !== timestamps.length) {
      telemetryRateLimitMap.set(projectId, active);
    }
  }
}

function checkTelemetryRateLimit(projectId: string, now: number): boolean {
  cleanTelemetryRateLimits(now);
  const windowMs = 60_000;
  const maxBatches = 120;
  const rawTimestamps = telemetryRateLimitMap.get(projectId);
  const timestamps = (rawTimestamps || []).filter(t => t > now - windowMs);

  if (rawTimestamps && timestamps.length === 0) {
    telemetryRateLimitMap.delete(projectId);
  }

  if (timestamps.length >= maxBatches) {
    telemetryRateLimitMap.set(projectId, timestamps);
    return false;
  }

  timestamps.push(now);
  telemetryRateLimitMap.set(projectId, timestamps);
  return true;
}

// DLP Redaction on preview to prevent telemetry leakage
export function redactSensitiveTelemetry(preview: unknown): unknown {
  if (!preview) return null;
  const str = typeof preview === 'string' ? preview : JSON.stringify(preview);

  // Redact API keys, tokens, auth headers, and private keys
  const redacted = str
    .replace(/(?:mcpshld_live_|sk_live_|ghp_|gho_|ghu_|ghs_|glpat-)[A-Za-z0-9_\-]{16,}/g, '[REDACTED_API_KEY]')
    .replace(/(?:Bearer\s+)[A-Za-z0-9_\-\.]{20,}/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/(?:"password"|"secret"|"token")\s*:\s*"[^"]+"/gi, '"secret":"[REDACTED]"');

  try {
    return JSON.parse(redacted);
  } catch {
    return redacted;
  }
}

const TelemetryEventSchema = z.object({
  sessionId: z.string().min(1).max(128),
  eventType: z.string().min(1).max(64),
  detector: z.string().max(64).optional(),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  toolName: z.string().max(128).optional(),
  reason: z.string().max(512).optional(),
  sanitizedPreview: z.unknown().optional(),
  clientTimestamp: z.number().optional(),
});

const TelemetryBatchSchema = z.object({
  device: z.record(z.string(), z.unknown()).optional(),
  events: z.array(TelemetryEventSchema).min(1, 'Events array must not be empty').max(100, 'Events array cannot exceed 100 entries'),
});

export function verifyHmac(payload: string, timestamp: string, key: string, expectedSignature: string): boolean {
  try {
    const dataToSign = `${timestamp}:${payload}`;
    const hmac = crypto.createHmac('sha256', key).update(dataToSign).digest('hex');

    const cleanExpected = (expectedSignature || '').trim().toLowerCase();
    const cleanActual = hmac.toLowerCase();

    if (cleanExpected.length !== 64 || cleanActual.length !== 64) return false;

    const bufA = Buffer.from(cleanActual, 'hex');
    const bufB = Buffer.from(cleanExpected, 'hex');
    if (bufA.length !== 32 || bufB.length !== 32) return false;

    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

export async function POST(req: Request) {
  const requestId = req.headers.get('x-request-id') || `tel-${crypto.randomUUID()}`;

  const signature = req.headers.get('X-MCP-Shield-Signature');
  const timestamp = req.headers.get('X-MCP-Shield-Timestamp');
  const authHeader = req.headers.get('authorization') || '';
  const clientProvidedKey = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : (req.headers.get('X-MCP-Shield-Key') || '').trim();

  if (!signature || !timestamp || !clientProvidedKey) {
    return jsonError('MISSING_HEADERS', 'Missing required security headers (Signature, Timestamp, Key)', 401, requestId);
  }

  // 1. Clock skew check (max 5 minutes)
  const now = Date.now();
  const parsedTimestamp = parseInt(timestamp, 10);
  if (isNaN(parsedTimestamp) || Math.abs(now - parsedTimestamp) > 5 * 60 * 1000) {
    return jsonError('TIMESTAMP_OUT_OF_BOUNDS', 'Request timestamp clock skew exceeds 5-minute allowance', 401, requestId);
  }

  const rawBody = await req.text();

  // 2. High-Entropy Nonce & Distributed Replay Protection (SEC-FINDINGS 005 & 012)
  const keyPrefix = clientProvidedKey.length >= 16 ? clientProvidedKey.substring(0, 16) : clientProvidedKey;
  const nonce = req.headers.get('X-MCP-Shield-Nonce') ||
    crypto.createHash('sha256').update(`${keyPrefix}:${timestamp}:${rawBody}`).digest('hex');

  const distributedStore = getDistributedStateStore();
  const isNonceFresh = await distributedStore.consumeNonce(nonce, 300);
  if (!isNonceFresh) {
    return jsonError('REPLAY_DETECTED', 'Replay detected: Nonce has already been consumed', 401, requestId);
  }

  // Backward compatibility check for local memory cache
  cleanReplayCache(now);
  if (recentNonceCache.has(nonce)) {
    return jsonError('REPLAY_DETECTED', 'Replay detected: Nonce has already been consumed', 401, requestId);
  }
  recentNonceCache.set(nonce, now + 5 * 60 * 1000);

  const supabaseAdmin = createAdminSupabaseClient();

  // 3. Resolve Project and Key from Key Prefix
  const { data: keyRecords, error: keyErr } = await supabaseAdmin
    .from('api_keys')
    .select('id, project_id, key_hash, revoked, expires_at')
    .eq('key_prefix', keyPrefix);

  if (keyErr || !keyRecords || keyRecords.length === 0) {
    return jsonError('UNAUTHORIZED_KEY', 'Invalid or unassociated API key prefix', 401, requestId);
  }

  const activeRecord = keyRecords.find(r => !r.revoked && (!r.expires_at || new Date(r.expires_at).getTime() > now));
  if (!activeRecord) {
    return jsonError('REVOKED_KEY', 'API key has been revoked or expired', 401, requestId);
  }

  // 4. Verify API Key Authenticity & Separate HMAC Secret Material (SEC-FINDING-003)
  // Constant-time comparison: Verifier key_hash is one-way SHA-256 and never used as symmetric secret
  const computedHash = crypto.createHash('sha256').update(clientProvidedKey).digest('hex');
  const bufComputed = Buffer.from(computedHash);
  const bufExpected = Buffer.from(activeRecord.key_hash);
  const isKeyValid = bufComputed.length === bufExpected.length && crypto.timingSafeEqual(bufComputed, bufExpected);

  if (!isKeyValid) {
    return jsonError('UNAUTHORIZED_KEY', 'API key cryptographic verification failed', 401, requestId);
  }

  // Derive separate HKDF secret from raw key so database key_hash leak cannot sign telemetry
  const derivedHmacSecret = deriveTelemetryHmacSecret(clientProvidedKey);
  const isValidSig =
    verifyHmac(rawBody, timestamp, derivedHmacSecret, signature) ||
    verifyHmac(rawBody, timestamp, clientProvidedKey, signature);

  if (!isValidSig) {
    return jsonError('INVALID_SIGNATURE', 'HMAC signature verification failed', 401, requestId);
  }

  // 5. Distributed & Per-Project Rate Limiting (SEC-FINDINGS 005 & 014)
  const rlResult = await distributedStore.checkRateLimit(`telemetry_rl:${activeRecord.project_id}`, 120, 60);
  if (!rlResult.allowed || !checkTelemetryRateLimit(activeRecord.project_id, now)) {
    return jsonError('RATE_LIMITED', 'Telemetry ingestion rate limit exceeded for this project', 429, requestId);
  }

  // 6. Schema Validation
  let bodyJson: unknown;
  try {
    bodyJson = JSON.parse(rawBody);
  } catch {
    return jsonError('MALFORMED_JSON', 'Request body must be valid JSON', 400, requestId);
  }

  const parseResult = TelemetryBatchSchema.safeParse(bodyJson);
  if (!parseResult.success) {
    return jsonError(
      'VALIDATION_FAILED',
      'Telemetry payload schema validation failed',
      400,
      requestId,
      parseResult.error.issues.map(i => `${i.path.join('.')}: ${i.message}`)
    );
  }

  // 7. Redact and Store Events
  const eventsToInsert = parseResult.data.events.map(event => ({
    project_id: activeRecord.project_id,
    session_id: event.sessionId,
    event_type: event.eventType,
    detector: event.detector || null,
    risk_level: event.riskLevel || 'LOW',
    tool_name: event.toolName || null,
    reason: event.reason || null,
    sanitized_preview: event.sanitizedPreview ? JSON.stringify(redactSensitiveTelemetry(event.sanitizedPreview)) : null,
    client_timestamp: event.clientTimestamp || now,
  }));

  const { error: insertErr } = await supabaseAdmin.from('security_events').insert(eventsToInsert);

  if (insertErr) {
    console.error('Failed to insert telemetry events:', insertErr);
    return jsonError('STORAGE_ERROR', 'Failed to store security telemetry', 500, requestId);
  }

  return jsonSuccess({
    success: true,
    acceptedEvents: eventsToInsert.length,
    projectId: activeRecord.project_id,
  });
}
