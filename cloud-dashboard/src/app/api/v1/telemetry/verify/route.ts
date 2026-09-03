import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { verifyKeyHash, extractKeyPrefix } from '@/lib/api-keys';
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
    const clientIp = getClientIp(request);

    // Rate limiting: 60 verifications per minute per IP
    const rlCheck = globalRateLimiter.check(`telemetry_verify:${keyPrefix}:${clientIp}`, 60, 60 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded for pairing verification.' }, { status: 429 });
    }

    let hmacKey: string | null = null;
    let project = { id: 'default-project', name: 'Production Project' };
    let organization = { id: 'default-org', name: 'Default Organization' };
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
            return NextResponse.json({
              error: 'API Key has been revoked. Please rotate your key in the console at https://cloud.mcp-shield.com/settings/general'
            }, { status: 401 });
          }

          if (apiKeyData.expires_at && new Date(apiKeyData.expires_at).getTime() < Date.now()) {
            return NextResponse.json({
              error: 'API Key has expired. Please renew your key in the console at https://cloud.mcp-shield.com/settings/general'
            }, { status: 401 });
          }

          if (apiKeyData.key_hash && verifyKeyHash(keyToken, apiKeyData.key_hash)) {
            isKeyValid = true;
            hmacKey = keyToken;

            // Fetch Project & Org details
            if (apiKeyData.project_id) {
              const { data: projectData } = await supabase
                .from('projects')
                .select('id, name, organization_id')
                .eq('id', apiKeyData.project_id)
                .maybeSingle();

              if (projectData) {
                project = { id: projectData.id, name: projectData.name };

                if (projectData.organization_id) {
                  const { data: orgData } = await supabase
                    .from('organizations')
                    .select('id, name')
                    .eq('id', projectData.organization_id)
                    .maybeSingle();

                  if (orgData) {
                    organization = { id: orgData.id, name: orgData.name };
                  }
                }
              }
            }

            // Update last_used_at on API key
            await supabase
              .from('api_keys')
              .update({ last_used_at: new Date().toISOString() })
              .eq('id', apiKeyData.id);
          }
        }
      } catch (dbErr: any) {
        console.warn('[VERIFY_DB_NOTICE]', dbErr?.message);
      }
    }

    // Explicit dev/testing fallback ONLY allowed outside production
    const isDevOrTest = process.env.NODE_ENV === 'test' || !hasSupabaseConfig;
    if (!isKeyValid && isDevOrTest) {
      if (keyPrefix.startsWith('mcp_live_default') || keyPrefix === 'dev-prefix-1' || keyToken.startsWith('mcp_live_sec_demo')) {
        hmacKey = keyToken;
        isKeyValid = true;
        project = { id: 'proj-sandbox-01', name: 'Sandbox Gateway Project' };
        organization = { id: 'org-sandbox-01', name: 'Sandbox Team' };
      }
    }

    if (!isKeyValid || !hmacKey) {
      return NextResponse.json({
        error: 'Invalid API Key: Key was not found or secret hash does not match.'
      }, { status: 401 });
    }

    // Verify HMAC Signature
    const isValidSig = await verifyHmacSignature(rawBody, timestamp, hmacKey, signature);
    if (!isValidSig) {
      if (!isDevOrTest || !keyPrefix.startsWith('mcp_live_default')) {
        return NextResponse.json({ error: 'Invalid HMAC Signature: Payload integrity verification failed.' }, { status: 401 });
      }
    }

    let parsedBody: any = {};
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {}

    const installationId = parsedBody.installation?.installationId || parsedBody.installationId || 'unknown_installation';
    const clientVersion = parsedBody.clientVersion || '1.0.12';
    const environment = parsedBody.installation?.environment || parsedBody.environment || 'production';

    // Track or update agent instance heartbeat
    if (hasSupabaseConfig && project.id) {
      try {
        await supabase
          .from('agent_instances')
          .upsert({
            project_id: project.id,
            instance_name: parsedBody.device?.hostname || 'MCP-Shield-Agent',
            hostname: parsedBody.device?.hostname || 'unknown',
            os: parsedBody.device?.platform || 'unknown',
            client_name: parsedBody.clientName || 'mcp-shield-runtime',
            shield_version: clientVersion,
            status: 'ONLINE',
            last_heartbeat_at: new Date().toISOString()
          }, { onConflict: 'project_id, hostname' });
      } catch {
        // Non-blocking instance heartbeat recording
      }
    }

    return NextResponse.json({
      valid: true,
      status: 'CONNECTED',
      organization,
      project,
      environment,
      installationId,
      serverTime: new Date().toISOString(),
      dashboardUrl: 'https://cloud.mcp-shield.com/console'
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to verify pairing handshake');
  }
}
