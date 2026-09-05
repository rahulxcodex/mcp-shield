import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { createAdminSupabaseClient, supabase as adminSupabase } from '@/lib/supabase';
import { getAuthenticatedUserWithBearer, verifyOrgMembership } from '@/lib/authz';

export const runtime = 'nodejs';

interface EnterprisePolicyRule {
  id: string;
  name: string;
  category: 'NETWORK' | 'SHELL' | 'FILESYSTEM' | 'DLP' | 'RUNTIME';
  effect: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  condition: string;
  version: number;
  inheritedFrom?: string;
  environment: 'production' | 'staging' | 'development';
}

const DEFAULT_ENTERPRISE_POLICIES: ReadonlyArray<EnterprisePolicyRule> = Object.freeze([
  {
    id: 'POL-NET-001',
    name: 'Zero-Trust SSRF & Link-Local Quarantine',
    category: 'NETWORK',
    effect: 'BLOCK',
    condition: 'destination in [169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]',
    version: 3,
    environment: 'production',
  },
  {
    id: 'POL-DLP-002',
    name: 'Bijective FPE Secret Tokenization',
    category: 'DLP',
    effect: 'SANITIZE',
    condition: 'payload.matches(AWS_KEY | GITHUB_PAT | RSA_PRIVATE_KEY)',
    version: 4,
    environment: 'production',
  },
  {
    id: 'POL-SHELL-003',
    name: 'Subshell AST Chaining & Fork Bomb Prevention',
    category: 'SHELL',
    effect: 'BLOCK',
    condition: 'ast.contains(CommandSubstitution | PipeInterpreter | ForkBomb)',
    version: 2,
    environment: 'production',
  },
  {
    id: 'POL-RUNTIME-004',
    name: 'Multi-Agent Delegation Depth Cap (Depth <= 5)',
    category: 'RUNTIME',
    effect: 'QUARANTINE',
    condition: 'agent.delegation_depth > 5',
    version: 1,
    environment: 'production',
  },
]);

export async function GET(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { user, error: authErr } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);
    if (!user || authErr) {
      return NextResponse.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const environment = searchParams.get('env') || 'production';
    const category = searchParams.get('category');
    const orgId = searchParams.get('organization_id') || req.headers.get('x-organization-id');

    let combinedPolicies: EnterprisePolicyRule[] = [...DEFAULT_ENTERPRISE_POLICIES];

    if (orgId) {
      const memberCheck = await verifyOrgMembership(supabase, orgId, user.id, 'viewer');
      if (!memberCheck.authorized) {
        return NextResponse.json({ error: memberCheck.error || 'Forbidden: Access denied' }, { status: 403 });
      }

      // Merge tenant-specific custom policies from database
      const { data: bundle } = await adminSupabase
        .from('policy_bundles')
        .select('rules')
        .eq('organization_id', orgId)
        .eq('is_active', true)
        .maybeSingle();

      if (bundle && Array.isArray(bundle.rules)) {
        const tenantRules: EnterprisePolicyRule[] = bundle.rules;
        const tenantRuleIds = new Set(tenantRules.map((r) => r.id));
        const filteredDefaults = DEFAULT_ENTERPRISE_POLICIES.filter((r) => !tenantRuleIds.has(r.id));
        combinedPolicies = [...tenantRules, ...filteredDefaults];
      }
    }

    let filtered = combinedPolicies.filter((p) => p.environment === environment);
    if (category) {
      filtered = filtered.filter((p) => p.category.toLowerCase() === category.toLowerCase());
    }

    return NextResponse.json({
      success: true,
      organizationId: orgId || null,
      environment,
      policiesCount: filtered.length,
      policies: filtered,
      syncedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to fetch policies' }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { user, error: authErr } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);
    if (!user || authErr) {
      return NextResponse.json({ error: 'Unauthorized: Enterprise credentials required' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const orgId = body.organizationId || req.headers.get('x-organization-id');

    if (!orgId) {
      return NextResponse.json({ error: 'Missing required organization context (organizationId)' }, { status: 400 });
    }

    const authCheck = await verifyOrgMembership(supabase, orgId, user.id, 'admin');
    if (!authCheck.authorized) {
      return NextResponse.json({ error: authCheck.error || 'Forbidden: Admin or Owner role required to modify organization policies' }, { status: 403 });
    }

    if (!body.name || !body.category || !body.effect) {
      return NextResponse.json({ error: 'Missing required fields: name, category, effect' }, { status: 400 });
    }

    const validCategories = ['NETWORK', 'SHELL', 'FILESYSTEM', 'DLP', 'RUNTIME'];
    const validEffects = ['ALLOW', 'BLOCK', 'SANITIZE', 'QUARANTINE'];

    if (!validCategories.includes(body.category.toUpperCase())) {
      return NextResponse.json({ error: `Invalid category. Allowed: ${validCategories.join(', ')}` }, { status: 400 });
    }
    if (!validEffects.includes(body.effect.toUpperCase())) {
      return NextResponse.json({ error: `Invalid effect. Allowed: ${validEffects.join(', ')}` }, { status: 400 });
    }

    const newRule: EnterprisePolicyRule = {
      id: `POL-CUSTOM-${Date.now().toString(36).toUpperCase()}`,
      name: body.name.trim(),
      category: body.category.toUpperCase(),
      effect: body.effect.toUpperCase(),
      condition: body.condition || 'custom_expression',
      version: 1,
      environment: body.environment || 'production',
    };

    // Store custom policy scoped to the tenant's policy_bundles table in database
    const { data: existingBundle } = await adminSupabase
      .from('policy_bundles')
      .select('id, rules, policy_version')
      .eq('organization_id', orgId)
      .eq('is_active', true)
      .maybeSingle();

    const existingRules: EnterprisePolicyRule[] = (existingBundle?.rules as EnterprisePolicyRule[]) || [];
    const updatedRules = [newRule, ...existingRules];
    const now = new Date().toISOString();

    if (existingBundle?.id) {
      await adminSupabase
        .from('policy_bundles')
        .update({
          rules: updatedRules,
          policy_version: `${existingBundle.policy_version || '1.0.0'}-rev`,
        })
        .eq('id', existingBundle.id);
    } else {
      await adminSupabase
        .from('policy_bundles')
        .insert([{
          organization_id: orgId,
          manifest_version: '2.0.0',
          policy_version: '1.0.0',
          rules: updatedRules,
          algorithm: 'Ed25519',
          signature: 'tenant_custom_bundle',
          is_active: true,
          expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: now,
        }]);
    }

    return NextResponse.json({
      success: true,
      organizationId: orgId,
      message: 'Enterprise policy rule committed successfully for organization',
      rule: newRule,
    }, { status: 201 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Invalid policy JSON payload' }, { status: 400 });
  }
}

