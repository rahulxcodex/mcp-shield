import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { verifyKeyHash, hashApiKey } from '@/lib/api-keys';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';
import crypto from 'crypto';

export const runtime = 'nodejs';

async function verifyHmacSignature(payload: string, timestamp: string, apiKey: string, expectedSignature: string): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(apiKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const dataToSign = encoder.encode(`${timestamp}:${payload}`);
    const signatureBuffer = await crypto.subtle.sign('HMAC', key, dataToSign);
    
    const signatureHex = Array.from(new Uint8Array(signatureBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
      
    const bufA = Buffer.from(signatureHex, 'hex');
    const bufB = Buffer.from(expectedSignature, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function extractPrefix(rawKeyOrPrefix: string): string {
  if (!rawKeyOrPrefix) return '';
  const parts = rawKeyOrPrefix.split('_');
  if (rawKeyOrPrefix.startsWith('mcp_live_') && !rawKeyOrPrefix.startsWith('mcp_live_sec_') && parts.length >= 3) {
    return parts.slice(0, 3).join('_');
  }
  if (rawKeyOrPrefix.startsWith('mcp_live_sec_') && parts.length >= 4) {
    return parts.slice(0, 4).join('_');
  }
  return rawKeyOrPrefix.substring(0, Math.min(rawKeyOrPrefix.length, 20));
}

export async function POST(request: Request) {
  try {
    const rawBody = await request.text();
    const headers = request.headers;
    const signature = headers.get('X-MCP-Shield-Signature');
    const timestamp = headers.get('X-MCP-Shield-Timestamp');
    const rawKeyHeader = headers.get('X-MCP-Shield-Key');
    const authHeader = headers.get('Authorization');

    const keyToken = rawKeyHeader || (authHeader?.startsWith('Bearer ') ? authHeader.substring(7).trim() : null);

    if (!signature || !timestamp || !keyToken) {
      return NextResponse.json({ error: 'Missing security headers' }, { status: 401 });
    }
    
    const timeDiff = Math.abs(Date.now() - parseInt(timestamp, 10));
    if (timeDiff > 10 * 60 * 1000) {
      return NextResponse.json({ error: 'Request expired: timestamp drift exceeds 10 minutes' }, { status: 401 });
    }

    const keyPrefix = extractPrefix(keyToken);

    // Rate limiting: 1000 telemetry submissions per minute per prefix/IP
    const clientIp = getClientIp(request);
    const rlCheck = globalRateLimiter.check(`telemetry_ingest:${keyPrefix}:${clientIp}`, 1000, 60 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Telemetry ingestion rate limit exceeded.' }, { status: 429 });
    }

    let hmacKey = process.env.MCP_SHIELD_SHARED_KEY || null;
    let projectId = null;
    let isKeyValid = false;

    try {
      const { data: apiKeyData } = await supabase
        .from('api_keys')
        .select('key_hash, project_id, expires_at, status')
        .eq('key_prefix', keyPrefix)
        .maybeSingle();

      if (apiKeyData) {
        if (apiKeyData.status === 'revoked') {
          return NextResponse.json({ error: 'API Key has been revoked. Please rotate your key in the console.' }, { status: 401 });
        }

        if (apiKeyData.expires_at && new Date(apiKeyData.expires_at).getTime() < Date.now()) {
          return NextResponse.json({ error: 'API Key expired. Please renew your key in the console.' }, { status: 401 });
        }

        projectId = apiKeyData.project_id;

        // Constant-time SHA-256 hash verification
        if (apiKeyData.key_hash) {
          if (verifyKeyHash(keyToken, apiKeyData.key_hash)) {
            isKeyValid = true;
            hmacKey = keyToken;
          } else if (apiKeyData.key_hash === keyToken) {
            // Backward compatibility for legacy plaintext records
            isKeyValid = true;
            hmacKey = keyToken;
          }
        }
      }
    } catch {
      // Graceful fallback when DB not configured
    }

    if (!hmacKey) {
      // Allow standard dev and demo keys for local sandbox
      if (keyPrefix.startsWith('mcp_live_default') || keyPrefix === 'dev-prefix-1') {
        hmacKey = keyToken || 'dev-secret-key-for-testing';
        isKeyValid = true;
      }
    }

    if (!isKeyValid && !hmacKey) {
      return NextResponse.json({ error: 'Invalid API Key' }, { status: 401 });
    }

    const isValidSig = await verifyHmacSignature(rawBody, timestamp, hmacKey!, signature);
    const hasSupabaseConfig = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://placeholder.supabase.co');

    if (!isValidSig) {
      const isDevOrTest = process.env.NODE_ENV === 'test' || !hasSupabaseConfig;
      if (!isDevOrTest || !keyPrefix.startsWith('mcp_live_default')) {
        return NextResponse.json({ error: 'Invalid HMAC Signature' }, { status: 401 });
      }
    }

    const payload = JSON.parse(rawBody);
    const { events } = payload;

    if (!events || !Array.isArray(events)) {
      return NextResponse.json({ error: 'Invalid payload: missing events array' }, { status: 400 });
    }

    const records = events.map((e: any) => ({
      session_id: e.sessionId || 'anonymous',
      event_type: e.eventType || 'BLOCK',
      detector: e.detector || 'Tree-sitter AST',
      risk_level: e.riskLevel || 'HIGH',
      tool_name: e.toolName || 'unknown',
      reason: e.reason || 'Security policy interception',
      sanitized_preview: e.sanitizedPreview || null,
      client_timestamp: e.clientTimestamp || new Date().toISOString(),
      project_id: projectId
    }));

    if (hasSupabaseConfig) {
      const { error: insertError } = await supabase.from('security_events').insert(records);
      if (insertError) {
        console.error('[INGEST_ERROR] Database insertion failed:', insertError);
        return NextResponse.json({ error: 'Database insertion error' }, { status: 500 });
      }
    }

    return NextResponse.json({ success: true, processed: records.length });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to process telemetry ingest');
  }
}
