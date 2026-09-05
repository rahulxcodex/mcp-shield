import { createClient } from '@/utils/supabase/server';
import { createAdminSupabaseClient } from '@/lib/supabase';
import { getAuthenticatedUser, verifyOrgMembership } from '@/lib/authz';
import { resolveProjectFromApiKey } from '@/lib/api-keys';
import { jsonSuccess, jsonError } from '@/lib/api-response';
import * as crypto from 'crypto';

export const runtime = 'nodejs';

export interface PolicyRule {
  id: string;
  name: string;
  action: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'PROMPT';
  target: 'tool_call' | 'tool_output' | 'system_command' | 'network_egress';
  condition: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface SignedPolicyManifest {
  manifestVersion: string;
  policyVersion: string;
  organizationId: string;
  projectId?: string;
  policyType: 'baseline' | 'tenant_custom';
  isBaselineOnly: boolean;
  issuedAt: number;
  expiresAt: number;
  algorithm: 'Ed25519';
  rules: PolicyRule[];
  signature: string;
}

const BASELINE_PRODUCTION_RULES: PolicyRule[] = [
  {
    id: 'SEC-POL-001',
    name: 'Block Destructive Filesystem Execution',
    action: 'BLOCK',
    target: 'system_command',
    condition: 'cmd.matches("(rm\\s+-rf|del\\s+/s|format\\s+[a-z]:|mkfs)")',
    message: 'Destructive filesystem manipulation commands are strictly blocked by security policy.',
    severity: 'CRITICAL',
  },
  {
    id: 'SEC-POL-002',
    name: 'Bijective Secret DLP Sanitization',
    action: 'SANITIZE',
    target: 'tool_output',
    condition: 'output.containsPattern("SECRET_OR_API_KEY")',
    message: 'Cryptographic secret pattern detected and sanitized via format-preserving DLP vault.',
    severity: 'HIGH',
  },
  {
    id: 'SEC-POL-003',
    name: 'Prevent Untrusted Egress on Secret Read',
    action: 'QUARANTINE',
    target: 'network_egress',
    condition: 'session.hasReadLocalSecrets && egress.isUntrusted',
    message: 'Unverified outbound network egress quarantined following access to local credentials.',
    severity: 'CRITICAL',
  },
  {
    id: 'SEC-POL-004',
    name: 'Database Mutation Step-up Prompt',
    action: 'PROMPT',
    target: 'tool_call',
    condition: 'tool.name.matches("(sql_execute|query_db)") && args.query.matches("(DROP|ALTER|TRUNCATE)")',
    message: 'Irreversible database schema mutation requires human-in-the-loop authorization.',
    severity: 'HIGH',
  },
  {
    id: 'SEC-POL-005',
    name: 'Dynamic Code Evaluation Containment',
    action: 'BLOCK',
    target: 'tool_call',
    condition: 'tool.name == "eval" || args.command.matches("(eval|exec)\\s*\\(")',
    message: 'Dynamic in-memory code evaluation is prohibited under zero-trust enterprise posture.',
    severity: 'CRITICAL',
  },
];

const POLICY_VERSION = '2026.09.4';

export function signPolicyBundle(payloadString: string, privateKeyPem?: string): string {
  if (!privateKeyPem) {
    if (process.env.NODE_ENV === 'test') {
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      const signature = crypto.sign(null, Buffer.from(payloadString), privateKey);
      return signature.toString('base64');
    }
    throw new Error('ED25519_SIGNING_KEY_REQUIRED: Policy manifests must be signed with LICENSE_PRIVATE_KEY.');
  }

  try {
    const formattedKey = privateKeyPem.replace(/\\n/g, '\n').trim();
    const signature = crypto.sign(null, Buffer.from(payloadString), formattedKey);
    return signature.toString('base64');
  } catch (err: any) {
    console.error('Ed25519 Policy Signing Error:', err.message);
    throw new Error(`POLICY_SIGNING_FAILED: Failed to sign policy manifest with Ed25519 private key: ${err.message}`);
  }
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const organizationIdParam = url.searchParams.get('organization_id');
  const projectIdParam = url.searchParams.get('project_id');
  const apiKeyHeader = req.headers.get('X-MCP-Shield-Key') || req.headers.get('x-api-key');

  let effectiveOrgId = organizationIdParam || 'org-global';
  let effectiveProjectId = projectIdParam || undefined;

  // 1. Authenticate via User Session OR Project API Key
  if (apiKeyHeader) {
    const supabaseAdmin = createAdminSupabaseClient();
    const keyResolution = await resolveProjectFromApiKey(supabaseAdmin, apiKeyHeader);
    if (!keyResolution.valid || !keyResolution.projectId) {
      return jsonError('UNAUTHORIZED_API_KEY', 'Invalid or revoked API key', 401);
    }
    effectiveProjectId = keyResolution.projectId;
    if (keyResolution.organizationId) {
      effectiveOrgId = keyResolution.organizationId;
    }
  } else {
    const supabase = await createClient();
    const { user, error: authErr } = await getAuthenticatedUser(supabase);
    if (authErr || !user) {
      return jsonError('UNAUTHORIZED', 'Authentication required (Session or X-MCP-Shield-Key)', 401);
    }

    if (organizationIdParam) {
      const memberCheck = await verifyOrgMembership(supabase, organizationIdParam, user.id, 'viewer');
      if (!memberCheck.authorized) {
        return jsonError('FORBIDDEN', memberCheck.error || 'Access denied', 403);
      }
    }
  }

  // 2. Assemble Policy Bundle with Tenant Custom Rules (SEC-FINDING-008)
  let rules = [...BASELINE_PRODUCTION_RULES];
  let policyVersion = POLICY_VERSION;
  let isBaselineOnly = true;
  let policyType: 'baseline' | 'tenant_custom' = 'baseline';

  try {
    const supabaseAdmin = createAdminSupabaseClient();
    const { data: customBundle } = await supabaseAdmin
      .from('policy_bundles')
      .select('version, rules')
      .eq('organization_id', effectiveOrgId)
      .eq('is_active', true)
      .maybeSingle();

    if (customBundle) {
      if (customBundle.version) {
        policyVersion = `${POLICY_VERSION}-${customBundle.version}`;
      }
      if (Array.isArray(customBundle.rules) && customBundle.rules.length > 0) {
        // Merge tenant custom rules with baseline production rules (custom rules take precedence)
        const customRuleIds = new Set(customBundle.rules.map((r: any) => r.id));
        const filteredBaseline = BASELINE_PRODUCTION_RULES.filter(r => !customRuleIds.has(r.id));
        rules = [...customBundle.rules, ...filteredBaseline];
        isBaselineOnly = false;
        policyType = 'tenant_custom';
      }
    }
  } catch (dbErr: any) {
    console.warn('[POLICY_BUNDLE_DB_NOTICE]', dbErr?.message);
  }

  // 3. Compute ETag and Check Conditional Request
  const etag = `W/"policy-${policyVersion}-${effectiveOrgId}-${effectiveProjectId || 'all'}"`;
  const ifNoneMatch = req.headers.get('if-none-match');
  if (ifNoneMatch === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag } });
  }

  const now = Date.now();
  const expiresAt = now + 60 * 60 * 1000; // 1-hour cache TTL

  const unsignedManifest = {
    manifestVersion: '2.0.0',
    policyVersion,
    organizationId: effectiveOrgId,
    projectId: effectiveProjectId,
    policyType,
    isBaselineOnly,
    issuedAt: now,
    expiresAt,
    algorithm: 'Ed25519' as const,
    rules,
  };

  const payloadString = JSON.stringify(unsignedManifest);
  const signature = signPolicyBundle(payloadString, process.env.LICENSE_PRIVATE_KEY);

  const signedManifest: SignedPolicyManifest = {
    ...unsignedManifest,
    signature,
  };

  return jsonSuccess(signedManifest, 200, {
    ETag: etag,
    'Cache-Control': 'public, max-age=3600, must-revalidate',
  });
}
