import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { generateApiKey } from '@/lib/api-keys';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Rate limiting: max 10 project creations per hour
    const clientIp = getClientIp(req);
    const rlCheck = globalRateLimiter.check(`proj_create:${user.id}:${clientIp}`, 10, 3600 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json(
        { error: 'Rate limit exceeded: too many project creation attempts. Please try again later.' },
        { status: 429 }
      );
    }

    const { organization_id, project_name } = await req.json().catch(() => ({}));

    if (!organization_id) {
      return NextResponse.json({ error: 'Missing organization_id' }, { status: 400 });
    }

    // Server-side verification of organization membership (Prevents cross-org project creation)
    const { data: membership, error: memberErr } = await supabase
      .from('organization_members')
      .select('organization_id, role')
      .eq('organization_id', organization_id)
      .eq('user_id', user.id)
      .maybeSingle();

    if (memberErr || !membership) {
      return NextResponse.json(
        { error: 'Forbidden: You are not a member of the specified organization' },
        { status: 403 }
      );
    }

    // 1. Create project
    const { data: project, error: projErr } = await supabase
      .from('projects')
      .insert([{ organization_id, name: project_name || 'Default Project', slug: 'proj-' + Date.now() }])
      .select()
      .single();

    if (projErr) throw projErr;

    // 2. Generate secure API key with unique lookup prefix and SHA-256 hashed secret
    const keyInfo = generateApiKey({ name: 'Default Key', clientType: 'Gateway' });

    const { error: keyErr } = await supabase
      .from('api_keys')
      .insert([{
        project_id: project.id,
        name: keyInfo.name,
        key_prefix: keyInfo.keyPrefix,
        key_hash: keyInfo.keyHash, // Hashed with SHA-256; raw secret never stored
        expires_at: keyInfo.expiresAt,
        created_at: keyInfo.createdAt,
      }]);

    if (keyErr) throw keyErr;

    return NextResponse.json({
      project,
      apiKey: keyInfo.rawKey,
      keyPrefix: keyInfo.keyPrefix,
      createdAt: keyInfo.createdAt,
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to create project');
  }
}

