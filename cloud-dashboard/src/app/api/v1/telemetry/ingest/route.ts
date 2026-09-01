import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export const runtime = 'edge';

async function verifyHmacSignature(payload: string, timestamp: string, apiKey: string, expectedSignature: string): Promise<boolean> {
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
    
  return signatureHex === expectedSignature;
}

export async function POST(request: Request) {
  try {
    const rawBody = await request.text();
    const headers = request.headers;
    const signature = headers.get('X-MCP-Shield-Signature');
    const timestamp = headers.get('X-MCP-Shield-Timestamp');
    const keyPrefix = headers.get('X-MCP-Shield-Key');

    if (!signature || !timestamp || !keyPrefix) {
      return NextResponse.json({ error: 'Missing security headers' }, { status: 401 });
    }
    
    const timeDiff = Math.abs(Date.now() - parseInt(timestamp, 10));
    if (timeDiff > 5 * 60 * 1000) {
      return NextResponse.json({ error: 'Request expired' }, { status: 401 });
    }

    // Lookup API key by prefix
    const { data: apiKeyData, error: apiError } = await supabase
      .from('api_keys')
      .select('key, project_id')
      .eq('key_prefix', keyPrefix)
      .single();

    // Fallback for development if api_keys table is not seeded
    const apiKey = apiKeyData?.key || process.env.MCP_SHIELD_SHARED_KEY || (keyPrefix === 'dev-prefix-1' ? 'dev-secret-key-for-testing' : null);

    if (!apiKey) {
      return NextResponse.json({ error: 'Invalid API Key' }, { status: 401 });
    }

    const isValid = await verifyHmacSignature(rawBody, timestamp, apiKey, signature);
    
    if (!isValid) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }

    const payload = JSON.parse(rawBody);
    const { device, events } = payload;
    const projectId = apiKeyData?.project_id || null;

    if (!events || !Array.isArray(events)) {
      return NextResponse.json({ error: 'Invalid payload: missing events array' }, { status: 400 });
    }

    const eventsToInsert = events.map((event: any) => ({
      project_id: projectId,
      device_hostname: device?.hostname,
      device_platform: device?.platform,
      device_arch: device?.arch,
      session_id: event.sessionId,
      event_type: event.eventType,
      detector: event.detector,
      risk_level: event.riskLevel,
      tool_name: event.toolName,
      reason: event.reason,
      sanitized_preview: event.sanitizedPreview ? JSON.stringify(event.sanitizedPreview) : null,
      client_timestamp: event.clientTimestamp
    }));

    const { error } = await supabase.from('security_events').insert(eventsToInsert);

    if (error) {
      console.error('Supabase insertion error:', error);
      return NextResponse.json({ error: 'Database error' }, { status: 500 });
    }

    return NextResponse.json({ success: true, count: eventsToInsert.length });

  } catch (error) {
    console.error('Error processing telemetry:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
