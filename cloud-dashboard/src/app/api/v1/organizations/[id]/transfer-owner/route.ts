import { createClient } from '@/utils/supabase/server';
import { createAdminSupabaseClient } from '@/lib/supabase';
import { getAuthenticatedUser, verifyOrgMembership } from '@/lib/authz';
import { jsonSuccess, jsonError } from '@/lib/api-response';
import { z } from 'zod';

export const runtime = 'nodejs';

const TransferOwnershipSchema = z.object({
  targetUserId: z.string().uuid('targetUserId must be a valid UUID'),
  confirmation: z.literal('TRANSFER_OWNERSHIP'),
  reason: z.string().min(5, 'A clear reason for ownership transfer is required (min 5 chars)').max(500),
});

export async function POST(
  req: Request,
  context: { params: Promise<{ id: string }> }
) {
  const supabase = await createClient();
  const { user, error: authError } = await getAuthenticatedUser(supabase);

  if (authError || !user) {
    return jsonError('UNAUTHORIZED', 'Authentication required', 401);
  }

  const organizationId = (await context.params).id;

  // Strict check: Caller MUST be the current 'owner'
  const ownerCheck = await verifyOrgMembership(supabase, organizationId, user.id, 'owner');
  if (!ownerCheck.authorized || ownerCheck.role !== 'owner') {
    return jsonError('FORBIDDEN', 'Only the current organization owner can transfer ownership', 403);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('MALFORMED_JSON', 'Request body must be valid JSON', 400);
  }

  const parseResult = TransferOwnershipSchema.safeParse(body);
  if (!parseResult.success) {
    return jsonError(
      'VALIDATION_FAILED',
      'Invalid ownership transfer request',
      400,
      undefined,
      parseResult.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`)
    );
  }

  const { targetUserId, reason } = parseResult.data;

  if (targetUserId === user.id) {
    return jsonError('INVALID_TARGET', 'Cannot transfer ownership to yourself', 400);
  }

  const supabaseAdmin = createAdminSupabaseClient();

  // Execute Atomic Ownership Transfer via Database Transaction / Stored Procedure
  const { data: rpcResult, error: rpcErr } = await supabaseAdmin.rpc('transfer_organization_ownership', {
    p_org_id: organizationId,
    p_caller_id: user.id,
    p_target_id: targetUserId,
    p_reason: reason,
  });

  if (rpcErr) {
    console.error('Atomic ownership transfer failed:', rpcErr);
    const code = rpcErr.message?.includes('TARGET_NOT_MEMBER') ? 'TARGET_NOT_MEMBER' : 'TRANSFER_FAILED';
    const status = code === 'TARGET_NOT_MEMBER' ? 404 : 500;
    return jsonError(code, `Ownership transfer transaction failed: ${rpcErr.message}`, status);
  }

  return jsonSuccess({
    transferred: true,
    organizationId,
    previousOwnerId: user.id,
    newOwnerId: targetUserId,
    timestamp: new Date().toISOString(),
    details: rpcResult,
  });
}
