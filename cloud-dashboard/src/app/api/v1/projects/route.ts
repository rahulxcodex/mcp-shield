import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import crypto from 'crypto';

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    const { organization_id, project_name } = await req.json();

    // 1. Create a project
    const { data: project, error: projErr } = await supabase
      .from('projects')
      .insert([{ organization_id, name: project_name || 'Default Project', slug: 'proj-' + Date.now() }])
      .select()
      .single();

    if (projErr) throw projErr;

    // 2. Generate a secure API Key with unique lookup prefix
    const prefixId = crypto.randomBytes(4).toString('hex');
    const keyPrefix = `mcp_live_${prefixId}`;
    const rawKey = crypto.randomBytes(24).toString('hex');
    const apiKey = `${keyPrefix}_${rawKey}`;
    
    // In a real app, hash the full key, but for this demo, we store raw so CLI can use it via fallback if needed
    // Actually, backend verifyHmacSignature uses apiKeyData.key (so we need to store the raw key in `key` column for this demo)
    // Wait, migration says: name, key_prefix, key_hash.
    
    const { data: keyData, error: keyErr } = await supabase
      .from('api_keys')
      .insert([{ 
        project_id: project.id, 
        name: 'Default Key', 
        key_prefix: keyPrefix, 
        key_hash: apiKey // STUB: storing raw key in hash for the hacky verifyHmacSignature to work
      }])
      .select()
      .single();

    if (keyErr) throw keyErr;

    return NextResponse.json({ project, apiKey });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
