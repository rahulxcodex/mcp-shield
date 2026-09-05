import { createAdminSupabaseClient } from '@/lib/supabase';
import { jsonSuccess, jsonError } from '@/lib/api-response';
import { z } from 'zod';
import * as crypto from 'crypto';

export const runtime = 'nodejs';

const BreakGlassSchema = z.object({
  action: z.enum(['key_revoke', 'customer_suspend', 'billing_correct', 'policy_rollback']),
  targetId: z.string().min(1, 'Target ID is required'),
  reason: z.string().min(5, 'Mandatory reason required for administrative break-glass (min 5 chars)'),
  confirmation: z.literal('CONFIRM_BREAK_GLASS'),
  params: z.record(z.string(), z.any()).optional(),
});

interface AdminAuthResult {
  authorized: boolean;
  operatorId: string;
  operatorName: string;
}

function verifyAdminAuthorization(req: Request): AdminAuthResult {
  const authHeader = req.headers.get('authorization') || req.headers.get('x-admin-key');
  if (!authHeader) {
    return { authorized: false, operatorId: '', operatorName: '' };
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader.trim();
  const tokenBuf = Buffer.from(token);

  // 1. Check configured per-operator admin keys (SEC-FINDING-013)
  const operatorsConfig = process.env.ADMIN_OPERATORS;
  if (operatorsConfig) {
    try {
      const ops = operatorsConfig.trim().startsWith('[')
        ? JSON.parse(operatorsConfig)
        : operatorsConfig.split(',').map(s => {
            const [id, name, key] = s.trim().split(':');
            return { id, name, key };
          });
      for (const op of ops) {
        if (op.key && op.key.trim().length >= 24) {
          const keyBuf = Buffer.from(op.key.trim());
          if (keyBuf.length === tokenBuf.length && crypto.timingSafeEqual(keyBuf, tokenBuf)) {
            return {
              authorized: true,
              operatorId: op.id || 'admin-operator',
              operatorName: op.name || 'Administrative Operator'
            };
          }
        }
      }
    } catch {}
  }

  // 2. Check Master Key
  const adminSecret = process.env.ADMIN_MASTER_KEY;
  if (adminSecret && adminSecret.length >= 24) {
    const secretBuf = Buffer.from(adminSecret);
    if (secretBuf.length === tokenBuf.length && crypto.timingSafeEqual(secretBuf, tokenBuf)) {
      const operatorHeader = req.headers.get('x-admin-operator') || 'admin-primary';
      const operatorName = req.headers.get('x-admin-name') || 'Enterprise Admin';
      return { authorized: true, operatorId: operatorHeader, operatorName };
    }
  }

  return { authorized: false, operatorId: '', operatorName: '' };
}

export async function POST(req: Request) {
  const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || '127.0.0.1';
  const allowlistEnv = process.env.ADMIN_ALLOWED_IPS || process.env.ADMIN_IP_ALLOWLIST;
  if (allowlistEnv) {
    const allowedIps = allowlistEnv.split(',').map(ip => ip.trim());
    const isAllowed = allowedIps.includes(clientIp) || allowedIps.includes('*') || clientIp === '127.0.0.1' || clientIp === '::1';
    if (!isAllowed) {
      return jsonError('FORBIDDEN_IP', `Access denied: IP address ${clientIp} is not authorized for break-glass operations`, 403);
    }
  }

  const authResult = verifyAdminAuthorization(req);
  if (!authResult.authorized) {
    return jsonError('UNAUTHORIZED_ADMIN', 'Valid administrative master key required for break-glass operations', 401);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('MALFORMED_JSON', 'Request body must be valid JSON', 400);
  }

  const parseResult = BreakGlassSchema.safeParse(body);
  if (!parseResult.success) {
    return jsonError(
      'VALIDATION_FAILED',
      'Invalid administrative request parameters',
      400,
      undefined,
      parseResult.error.issues.map(i => `${i.path.join('.')}: ${i.message}`)
    );
  }

  const { action, targetId, reason, params } = parseResult.data;
  const supabaseAdmin = createAdminSupabaseClient();
  const now = new Date().toISOString();

  // Phase 1: Pre-Audit Logging (SEC-FINDING-007)
  // Durably record admin intent BEFORE mutating state. If audit logging fails, the mutation NEVER executes.
  const auditId = `aud-${crypto.randomUUID()}`;
  const preAuditRecord = {
    id: auditId,
    action: `ADMIN_BREAK_GLASS_${action.toUpperCase()}`,
    target_id: targetId,
    reason: `[INITIATED by ${authResult.operatorName} (${authResult.operatorId}) from ${clientIp}] ${reason}`,
    details: {
      status: 'INITIATED',
      operatorId: authResult.operatorId,
      operatorName: authResult.operatorName,
      operatorIp: clientIp,
      params: params || {},
    },
    created_at: now,
  };

  const { error: preAuditErr } = await supabaseAdmin.from('audit_logs').insert([preAuditRecord]);
  if (preAuditErr) {
    console.error('[BREAK_GLASS_PRE_AUDIT_FAILURE]', preAuditErr.message);
    return jsonError(
      'AUDIT_FAILURE',
      `CRITICAL: Durable pre-audit log persistence failed: ${preAuditErr.message}. Administrative operation aborted before execution.`,
      500
    );
  }

  // Phase 2: Execute State Mutation
  let details: Record<string, any> = {};

  try {
    switch (action) {
      case 'key_revoke': {
        const { error } = await supabaseAdmin
          .from('api_keys')
          .update({
            is_active: false,
            revoked_at: now,
            revocation_reason: reason,
          })
          .eq('id', targetId);

        if (error) throw error;
        details = { keyId: targetId, status: 'REVOKED' };
        break;
      }

      case 'customer_suspend': {
        const { error } = await supabaseAdmin
          .from('organizations')
          .update({
            subscription_status: 'suspended',
            updated_at: now,
          })
          .eq('id', targetId);

        if (error) throw error;
        details = { organizationId: targetId, status: 'SUSPENDED' };
        break;
      }

      case 'billing_correct': {
        const newPlan = params?.plan || 'free';
        const newStatus = params?.status || 'active';

        const { error } = await supabaseAdmin
          .from('organizations')
          .update({
            plan: newPlan,
            subscription_status: newStatus,
            updated_at: now,
          })
          .eq('id', targetId);

        if (error) throw error;
        details = { organizationId: targetId, correctedPlan: newPlan, correctedStatus: newStatus };
        break;
      }

      case 'policy_rollback': {
        // Rollback organization or global policy version
        const { error } = await supabaseAdmin
          .from('policy_bundles')
          .update({
            is_active: false,
            revoked_at: now,
          })
          .eq('id', targetId);

        if (error) throw error;
        details = { policyId: targetId, status: 'ROLLED_BACK' };
        break;
      }
    }

    // Phase 3: Record Audit Completion
    const completionRecord = {
      action: `ADMIN_BREAK_GLASS_${action.toUpperCase()}_COMPLETED`,
      target_id: targetId,
      reason,
      details: {
        ...details,
        initialAuditId: auditId,
        status: 'COMPLETED',
        operatorId: authResult.operatorId,
        operatorName: authResult.operatorName,
        operatorIp: clientIp,
      },
      created_at: new Date().toISOString(),
    };
    await supabaseAdmin.from('audit_logs').insert([completionRecord]);

    return jsonSuccess({
      success: true,
      action,
      targetId,
      details,
      timestamp: now,
      auditId,
    });
  } catch (err: any) {
    // Record mutation failure in audit log
    try {
      await supabaseAdmin.from('audit_logs').insert([{
        action: `ADMIN_BREAK_GLASS_${action.toUpperCase()}_FAILED`,
        target_id: targetId,
        reason: `FAILED: ${err.message}`,
        details: {
          initialAuditId: auditId,
          status: 'FAILED',
          error: err.message,
          operatorId: authResult.operatorId,
          operatorName: authResult.operatorName,
          operatorIp: clientIp,
        },
        created_at: new Date().toISOString(),
      }]);
    } catch {}

    console.error(`Break-glass operation ${action} on ${targetId} failed:`, err);
    return jsonError('OPERATION_FAILED', `Administrative operation failed: ${err.message || 'Internal error'}`, 500);
  }
}
