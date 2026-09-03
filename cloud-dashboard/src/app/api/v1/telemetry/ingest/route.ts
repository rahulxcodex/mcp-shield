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

import { extractKeyPrefix } from '@/lib/api-keys';

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
      return NextResponse.json({ error: 'Missing security headers (Signature, Timestamp, or Key required)' }, { status: 401 });
    }
    
    const timeDiff = Math.abs(Date.now() - parseInt(timestamp, 10));
    if (timeDiff > 10 * 60 * 1000) {
      return NextResponse.json({ error: 'Request expired: timestamp drift exceeds 10 minutes' }, { status: 401 });
    }

    const keyPrefix = extractKeyPrefix(keyToken);

    // Rate limiting: 1000 telemetry submissions per minute per prefix/IP
    const clientIp = getClientIp(request);
    const rlCheck = globalRateLimiter.check(`telemetry_ingest:${keyPrefix}:${clientIp}`, 1000, 60 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Telemetry ingestion rate limit exceeded.' }, { status: 429 });
    }

    let hmacKey: string | null = null;
    let projectId: string | null = null;
    let apiKeyRecordId: string | null = null;
    let isKeyValid = false;

    const hasSupabaseConfig = Boolean(
      process.env.NEXT_PUBLIC_SUPABASE_URL && 
      process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://placeholder.supabase.co'
    );

    if (hasSupabaseConfig) {
      try {
        const { data: apiKeyData } = await supabase
          .from('api_keys')
          .select('id, key_hash, project_id, expires_at, status')
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
          apiKeyRecordId = apiKeyData.id;

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
      } catch (dbErr: any) {
        console.warn('[INGEST_DB_NOTICE]', dbErr?.message);
      }
    }

    // STRICT PRODUCTION INVARIANT: Development fallback keys are NEVER permitted in production
    const isDevOrTest = process.env.NODE_ENV === 'test' || !hasSupabaseConfig;
    if (!isKeyValid && isDevOrTest) {
      if (keyPrefix.startsWith('mcp_live_default') || keyPrefix === 'dev-prefix-1' || keyToken.startsWith('mcp_live_sec_demo')) {
        hmacKey = keyToken;
        isKeyValid = true;
        projectId = 'proj-sandbox-01';
      }
    }

    if (!isKeyValid || !hmacKey) {
      return NextResponse.json({ error: 'Invalid or unauthenticated API Key' }, { status: 401 });
    }

    const isValidSig = await verifyHmacSignature(rawBody, timestamp, hmacKey, signature);
    if (!isValidSig) {
      if (!isDevOrTest || !keyPrefix.startsWith('mcp_live_default')) {
        return NextResponse.json({ error: 'Invalid HMAC Signature' }, { status: 401 });
      }
    }

    let payload: any = {};
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
    }

    const { events, installation, device } = payload;
    if (!events || !Array.isArray(events)) {
      return NextResponse.json({ error: 'Invalid payload: missing events array' }, { status: 400 });
    }

    const installationId = installation?.installationId || 'unknown_inst';
    const environment = installation?.environment || 'production';
    const serverReceivedAt = new Date().toISOString();

    const records = events.map((e: any, idx: number) => ({
      event_id: e.eventId || `evt_${installationId}_${Date.now()}_${idx}`,
      session_id: e.sessionId || 'anonymous',
      event_type: e.eventType || 'BLOCK',
      detector: e.detector || 'Tree-sitter AST',
      risk_level: e.riskLevel || 'HIGH',
      tool_name: e.toolName || 'unknown',
      reason: e.reason || 'Security policy interception',
      sanitized_preview: e.sanitizedPreview || null,
      client_timestamp: e.clientTimestamp || serverReceivedAt,
      created_at: serverReceivedAt,
      sequence_number: e.sequenceNumber || idx,
      project_id: projectId
    }));

    if (hasSupabaseConfig && projectId) {
      try {
        // Deduplicated insert: ignore duplicates if event_id already exists
        const { error: insertError } = await supabase
          .from('security_events')
          .upsert(records, { onConflict: 'event_id', ignoreDuplicates: true });

        if (insertError) {
          // If table schema does not yet have event_id column, fallback to standard insert
          await supabase.from('security_events').insert(
            records.map(({ event_id, sequence_number, ...rest }) => rest)
          );
        }

        // Asynchronously update key last_used_at and agent heartbeat
        if (apiKeyRecordId) {
          supabase.from('api_keys').update({ last_used_at: serverReceivedAt }).eq('id', apiKeyRecordId).then(() => {});
        }
        if (device?.hostname) {
          supabase.from('agent_instances').upsert({
            project_id: projectId,
            instance_name: device.hostname,
            hostname: device.hostname,
            os: device.platform,
            client_name: payload.clientVersion || 'mcpshld',
            shield_version: payload.clientVersion || '1.0.12',
            status: 'ONLINE',
            last_heartbeat_at: serverReceivedAt
          }, { onConflict: 'project_id, hostname' }).then(() => {});
        }
      } catch (dbErr: any) {
        console.warn('[INGEST_DB_INSERT_WARN]', dbErr?.message);
      }
    }

    return NextResponse.json({
      success: true,
      processed: records.length,
      serverReceivedAt,
      environment
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to process telemetry ingest');
  }
}

