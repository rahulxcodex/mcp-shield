import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { z } from 'zod';
import { createClient } from '@/utils/supabase/server';
import { supabase as adminSupabase } from '@/lib/supabase';
import { generateApiKey, hashApiKey, validateApiKeyStructure, extractKeyPrefix } from '@/lib/api-keys';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';
import { FEATURE_FLAGS } from '@/config/plans';
import { authorizeRoute, getAuthenticatedUserWithBearer } from '@/lib/authz';

export const runtime = 'nodejs';

const CreateKeySchema = z.object({
  name: z.string().trim().min(1, 'Name cannot be empty').max(100, 'Name cannot exceed 100 characters').default('MCP Agent Token'),
  clientType: z.string().trim().max(100).default('Generic MCP Client'),
  expiresInDays: z.coerce.number().int().min(1, 'Expiration must be at least 1 day').max(365, 'Expiration cannot exceed 365 days').default(90),
  seats: z.coerce.number().int().min(1, 'Seats must be at least 1').max(100, 'Seats cannot exceed 100').default(1),
});

const ImportKeySchema = z.object({
  rawKey: z.string().trim().min(8, 'Key must be at least 8 characters').max(512, 'Key too long').refine((k) => !k.startsWith('MASTER_'), {
    message: 'Master key import is strictly prohibited in customer endpoints. Use internal administrative tools.',
  }),
  name: z.string().trim().min(1, 'Name cannot be empty').max(100, 'Name cannot exceed 100 characters'),
});

const RotateKeySchema = z.object({
  keyId: z.string().trim().min(1).optional(),
  keyPrefix: z.string().trim().min(1).optional(),
  expiresInDays: z.coerce.number().int().min(1, 'Expiration must be at least 1 day').max(365, 'Expiration cannot exceed 365 days').default(90),
}).refine((data) => data.keyId || data.keyPrefix, {
  message: 'Missing keyId or keyPrefix for rotation',
});

async function getOrCreateProject(supabaseUser: any, user: any): Promise<string | null> {
  try {
    const { data: orgs } = await adminSupabase
      .from('organization_members')
      .select('organization_id')
      .eq('user_id', user.id);

    const orgIds = (orgs || []).map((o: any) => o.organization_id);

    if (orgIds.length > 0) {
      const { data: projects } = await adminSupabase
        .from('projects')
        .select('id')
        .in('organization_id', orgIds)
        .limit(1);

      if (projects && projects.length > 0) {
        return projects[0].id;
      }
    }

    // Auto-provision default organization and project if none exist
    const emailPrefix = (user.email || 'developer').split('@')[0].replace(/[^a-zA-Z0-9_-]/g, '');
    const orgName = `${emailPrefix.toUpperCase()}'s Fleet`;
    const orgSlug = `org-${user.id.slice(0, 8)}-${Date.now().toString(36)}`;

    const { data: newOrg, error: orgErr } = await adminSupabase
      .from('organizations')
      .insert([{ name: orgName, slug: orgSlug }])
      .select('id')
      .single();

    if (orgErr || !newOrg?.id) {
      console.warn('[KEYS] Organization auto-provision note:', orgErr?.message);
      return null;
    }

    await adminSupabase
      .from('organization_members')
      .insert([{ organization_id: newOrg.id, user_id: user.id, role: 'owner' }]);

    const { data: newProj, error: projErr } = await adminSupabase
      .from('projects')
      .insert([{ organization_id: newOrg.id, name: 'Default MCP Fleet', slug: 'default' }])
      .select('id')
      .single();

    if (projErr || !newProj?.id) {
      console.warn('[KEYS] Project auto-provision note:', projErr?.message);
      return null;
    }

    return newProj.id;
  } catch (err) {
    console.error('[KEYS] getOrCreateProject error:', err);
    return null;
  }
}

async function getAuthUser(req: Request, supabase: any) {
  const { user } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);
  return user;
}

export async function GET(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (user) {
      // Find projects owned by user's organization
      const { data: orgs } = await adminSupabase
        .from('organization_members')
        .select('organization_id')
        .eq('user_id', user.id);
      
      const orgIds = (orgs || []).map((o: any) => o.organization_id);
      
      const { data: projects } = await adminSupabase
        .from('projects')
        .select('id')
        .in('organization_id', orgIds.length > 0 ? orgIds : ['00000000-0000-0000-0000-000000000000']);
      
      const projectIds = (projects || []).map((p: any) => p.id);

      if (projectIds.length === 0) {
        return NextResponse.json({ keys: [] });
      }

      const { data: keys, error } = await adminSupabase
        .from('api_keys')
        .select('id, name, key_prefix, created_at, last_used_at, expires_at')
        .in('project_id', projectIds)
        .order('created_at', { ascending: false });

      if (!error && keys) {
        const mappedKeys = keys.map((k: any) => ({
          ...k,
          status: k.expires_at && new Date(k.expires_at).getTime() <= Date.now() ? 'revoked' : 'active'
        }));
        return NextResponse.json({ keys: mappedKeys });
      }
    }
  } catch (err: unknown) {
    console.warn('[KEYS_GET] Lookup notice:', err);
  }

  return NextResponse.json({ keys: [] });
}

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const orgHeader = req.headers.get('x-organization-id') || undefined;
    const authzResult = authorizeRoute(user, 'key.create', undefined, orgHeader);
    if (!authzResult.authorized) {
      return NextResponse.json({ error: `Forbidden: ${authzResult.reason || 'Insufficient permissions'}` }, { status: 403 });
    }

    // Rate limiting: max 10 key creations per hour per user
    const clientIp = getClientIp(req);
    const rateLimitKey = user ? `key_create:${user.id}` : `key_create:${clientIp}`;
    const rlCheck = globalRateLimiter.check(rateLimitKey, 10, 3600 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json(
        { error: 'Rate limit exceeded: maximum 10 API keys can be generated per hour.' },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const parseResult = CreateKeySchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: 'Validation failed',
          details: parseResult.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`)
        },
        { status: 400 }
      );
    }

    const { name: keyName, clientType, expiresInDays, seats } = parseResult.data;
    const displayName = seats > 1 ? `${keyName} (${clientType} - ${seats} Seats Single Key)` : `${keyName} (${clientType})`;

    // Generate secure API key with unique lookup prefix and SHA-256 hash
    const generated = generateApiKey({
      name: displayName,
      clientType,
      expiresInDays,
      seats,
    });

    let keyId = generated.keyId;

    if (user) {
      // Check if this hash was previously used or revoked (key non-reusability)
      if (FEATURE_FLAGS.ENFORCE_KEY_NON_REUSABILITY) {
        const { data: revokedCheck } = await adminSupabase
          .from('api_keys')
          .select('id, expires_at, revoked')
          .eq('key_hash', generated.keyHash)
          .maybeSingle();

        if (revokedCheck) {
          const isRevoked = revokedCheck.revoked || (revokedCheck.expires_at && new Date(revokedCheck.expires_at).getTime() <= Date.now());
          if (isRevoked) {
            return NextResponse.json(
              { error: 'This key has already been used or revoked. Used keys cannot be reused.' },
              { status: 400 }
            );
          }
        }
      }

      // Ensure valid project id
      const projectId = await getOrCreateProject(supabase, user);

      // Enforce 1 active key per account rule: rotate previous active keys
      if (FEATURE_FLAGS.ENFORCE_SINGLE_KEY_LIMIT && projectId) {
        const { data: allProjectKeys } = await adminSupabase
          .from('api_keys')
          .select('id, expires_at, revoked')
          .eq('project_id', projectId);

        const activeIds = (allProjectKeys || [])
          .filter((k: any) => !k.revoked && (!k.expires_at || new Date(k.expires_at).getTime() > Date.now()))
          .map((k: any) => k.id);

        if (activeIds.length > 0) {
          await adminSupabase
            .from('api_keys')
            .update({
              status: 'revoked',
              revoked: true,
              expires_at: '1970-01-01T00:00:00.000Z',
              revocation_reason: 'Rotated by Single Active Key Policy'
            })
            .in('id', activeIds);
        }
      }

      // Store SHA-256 hash in database - NEVER raw plaintext secret
      const { data: inserted, error: insertErr } = await adminSupabase
        .from('api_keys')
        .insert([{
          project_id: projectId,
          name: displayName,
          key_prefix: generated.keyPrefix,
          key_hash: generated.keyHash, // Secure SHA-256 hash
          status: 'active',
          revoked: false,
          expires_at: generated.expiresAt,
          created_at: generated.createdAt
        }])
        .select('id')
        .single();

      if (insertErr) {
        console.error('[KEYS_POST] Insert error:', insertErr);
        return NextResponse.json({ error: 'Failed to persist API key in database' }, { status: 500 });
      } else if (inserted?.id) {
        keyId = inserted.id;
      }
    }

    return NextResponse.json({
      success: true,
      key: {
        id: keyId,
        name: displayName,
        keyPrefix: generated.keyPrefix,
        apiKey: generated.rawKey, // Returned ONCE to client on creation
        created_at: generated.createdAt,
        expires_at: generated.expiresAt,
        seats,
        status: 'active'
      }
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to generate API key');
  }
}

/**
 * Key Rotation: Revokes a compromised or aged key and seamlessly provisions a replacement.
 */
export async function PATCH(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const orgHeader = req.headers.get('x-organization-id') || undefined;
    const authzResult = authorizeRoute(user, 'key.rotate', undefined, orgHeader);
    if (!authzResult.authorized) {
      return NextResponse.json({ error: `Forbidden: ${authzResult.reason || 'Insufficient permissions'}` }, { status: 403 });
    }

    const clientIp = getClientIp(req);
    const rlCheck = globalRateLimiter.check(`key_rotate:${user.id}:${clientIp}`, 10, 3600 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded for key rotation.' }, { status: 429 });
    }

    const body = await req.json().catch(() => ({}));
    const parseResult = RotateKeySchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: 'Validation failed',
          details: parseResult.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
        },
        { status: 400 }
      );
    }
    const { keyId, keyPrefix, expiresInDays } = parseResult.data;

    // Check user's project ownership
    const { data: orgs } = await adminSupabase
      .from('organization_members')
      .select('organization_id')
      .eq('user_id', user.id);
    const orgIds = (orgs || []).map((o: any) => o.organization_id);

    const { data: projects } = await adminSupabase
      .from('projects')
      .select('id')
      .in('organization_id', orgIds);
    const projectIds = (projects || []).map((p: any) => p.id);

    // Fetch existing key
    let keyQuery = adminSupabase
      .from('api_keys')
      .select('id, project_id, name')
      .in('project_id', projectIds);
    if (keyId) keyQuery = keyQuery.eq('id', keyId);
    else if (keyPrefix) keyQuery = keyQuery.eq('key_prefix', keyPrefix);

    const { data: existingKey, error: fetchErr } = await keyQuery.maybeSingle();
    if (fetchErr || !existingKey) {
      return NextResponse.json({ error: 'Key not found or not authorized' }, { status: 404 });
    }

    // 1. Mark existing key as revoked
    await adminSupabase
      .from('api_keys')
      .update({ expires_at: '1970-01-01T00:00:00.000Z' })
      .eq('id', existingKey.id);

    // 2. Generate replacement key for the same project
    const newKeyInfo = generateApiKey({
      name: `${existingKey.name} (Rotated)`,
      expiresInDays: Number(expiresInDays) || 90,
    });

    const { data: insertedNew } = await adminSupabase
      .from('api_keys')
      .insert([{
        project_id: existingKey.project_id,
        name: newKeyInfo.name,
        key_prefix: newKeyInfo.keyPrefix,
        key_hash: newKeyInfo.keyHash,
        expires_at: newKeyInfo.expiresAt,
        created_at: newKeyInfo.createdAt,
      }])
      .select('id')
      .single();

    return NextResponse.json({
      success: true,
      message: 'Key rotated successfully. Compromised key has been revoked.',
      revokedKeyId: existingKey.id,
      newKey: {
        id: insertedNew?.id || newKeyInfo.keyId,
        name: newKeyInfo.name,
        keyPrefix: newKeyInfo.keyPrefix,
        apiKey: newKeyInfo.rawKey,
        expires_at: newKeyInfo.expiresAt,
        created_at: newKeyInfo.createdAt,
        status: 'active',
      }
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to rotate API key');
  }
}

/**
 * Import Existing Key: Accepts a pre-existing API key, validates format,
 * hashes it, and stores without server-side generation.
 * Used by enterprise users receiving distributed keys.
 */
export async function PUT(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const orgHeader = req.headers.get('x-organization-id') || undefined;
    const authzResult = authorizeRoute(user, 'key.create', undefined, orgHeader);
    if (!authzResult.authorized) {
      return NextResponse.json({ error: `Forbidden: ${authzResult.reason || 'Insufficient permissions'}` }, { status: 403 });
    }

    const clientIp = getClientIp(req);
    const rlCheck = globalRateLimiter.check(`key_import:${user.id}:${clientIp}`, 10, 3600 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded for key imports.' }, { status: 429 });
    }

    const body = await req.json().catch(() => ({}));
    const parseResult = ImportKeySchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: 'Validation failed',
          details: parseResult.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`)
        },
        { status: 400 }
      );
    }

    const { rawKey, name } = parseResult.data;
    const trimmedKey = rawKey.trim();
    const keyHash = hashApiKey(trimmedKey);

    // Enforce key non-reusability: once a key is revoked/used, it cannot be reused
    if (FEATURE_FLAGS.ENFORCE_KEY_NON_REUSABILITY) {
      const { data: existingRevoked } = await adminSupabase
        .from('api_keys')
        .select('id, expires_at, revoked')
        .eq('key_hash', keyHash)
        .maybeSingle();

      if (existingRevoked) {
        const isRevoked = existingRevoked.revoked || (existingRevoked.expires_at && new Date(existingRevoked.expires_at).getTime() <= Date.now());
        if (isRevoked) {
          return NextResponse.json(
            { error: 'This key has already been used or revoked. Used keys cannot be reused.' },
            { status: 400 }
          );
        }
      }
    }

    // For mcp_live_* keys, extract prefix normally. For external keys, derive prefix from hash.
    const isMcpFormat = validateApiKeyStructure(trimmedKey);
    const keyPrefix = isMcpFormat
      ? extractKeyPrefix(trimmedKey)
      : `ext_${keyHash.substring(0, 12)}`;

    const displayName = name.trim();
    const now = new Date().toISOString();

    const projectId = await getOrCreateProject(supabase, user);

    if (projectId) {
      // Check if this exact key is already active in this project
      const { data: existingActive } = await adminSupabase
        .from('api_keys')
        .select('id, expires_at, revoked')
        .eq('key_hash', keyHash)
        .eq('project_id', projectId)
        .maybeSingle();

      if (existingActive) {
        const isRevoked = existingActive.revoked || (existingActive.expires_at && new Date(existingActive.expires_at).getTime() <= Date.now());
        if (isRevoked) {
          return NextResponse.json(
            { error: 'This key has already been used or revoked. Used keys cannot be reused.' },
            { status: 400 }
          );
        }

        return NextResponse.json({
          success: true,
          message: 'Key already imported and active.',
          key: {
            id: existingActive.id,
            name: displayName,
            keyPrefix,
            status: 'active'
          }
        });
      }

      // Enforce 1 active key per account rule: rotate previous active keys
      if (FEATURE_FLAGS.ENFORCE_SINGLE_KEY_LIMIT) {
        const { data: allProjectKeys } = await adminSupabase
          .from('api_keys')
          .select('id, expires_at, revoked')
          .eq('project_id', projectId);

        const activeIds = (allProjectKeys || [])
          .filter((k: any) => !k.revoked && (!k.expires_at || new Date(k.expires_at).getTime() > Date.now()))
          .map((k: any) => k.id);

        if (activeIds.length > 0) {
          await adminSupabase
            .from('api_keys')
            .update({
              status: 'revoked',
              revoked: true,
              expires_at: '1970-01-01T00:00:00.000Z',
              revocation_reason: 'Rotated by Single Active Key Policy on Key Import'
            })
            .in('id', activeIds);
        }
      }
    }

    // Store SHA-256 hash — never the raw key
    const { data: inserted, error: insertErr } = await adminSupabase
      .from('api_keys')
      .insert([{
        project_id: projectId,
        name: displayName,
        key_prefix: keyPrefix,
        key_hash: keyHash,
        status: 'active',
        revoked: false,
        created_at: now
      }])
      .select('id')
      .single();

    if (insertErr) {
      console.error('[KEYS_PUT] Insert error:', insertErr);
      return NextResponse.json({ error: 'Failed to store imported key in database' }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: 'Key imported successfully.',
      key: {
        id: inserted?.id || `key-import-${Date.now()}`,
        name: displayName,
        keyPrefix,
        status: 'active',
      }
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to import API key');
  }
}

export async function DELETE(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');
    const prefix = searchParams.get('prefix');

    if (!id && !prefix) {
      return NextResponse.json({ error: 'Missing key id or prefix' }, { status: 400 });
    }

    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const orgHeader = req.headers.get('x-organization-id') || undefined;
    const authzResult =  authorizeRoute(user, 'key.revoke', undefined, orgHeader);
    if (!authzResult.authorized) {
      return NextResponse.json({ error: `Forbidden: ${authzResult.reason || 'Insufficient permissions'}` }, { status: 403 });
    }

    if (user) {
      // Scope delete/revocation to caller's projects only
      const { data: orgs } = await adminSupabase
        .from('organization_members')
        .select('organization_id')
        .eq('user_id', user.id);
      const orgIds = (orgs || []).map((o: any) => o.organization_id);
      const { data: projects } = await adminSupabase
        .from('projects')
        .select('id')
        .in('organization_id', orgIds.length > 0 ? orgIds : ['00000000-0000-0000-0000-000000000000']);
      const projectIds = (projects || []).map((p: any) => p.id);

      if (projectIds.length > 0) {
        let query = adminSupabase.from('api_keys').update({ expires_at: '1970-01-01T00:00:00.000Z' }).in('project_id', projectIds);
        if (id) query = query.eq('id', id);
        else if (prefix) query = query.eq('key_prefix', prefix);
        await query;
      }
    }

    return NextResponse.json({ success: true, message: 'Key revoked successfully' });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to revoke key');
  }
}

