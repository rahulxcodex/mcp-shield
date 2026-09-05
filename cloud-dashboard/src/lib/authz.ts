import { SupabaseClient, User } from '@supabase/supabase-js';

export type OrganizationRole = 'owner' | 'admin' | 'member' | 'viewer';

const ROLE_HIERARCHY: Record<OrganizationRole, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  viewer: 1,
};

export interface MembershipRecord {
  id: string;
  organization_id: string;
  user_id: string;
  role: OrganizationRole;
  created_at: string;
}

export async function getAuthenticatedUser(supabase: SupabaseClient): Promise<{ user: User | null; error: string | null }> {
  try {
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
      return { user: null, error: error?.message || 'Authentication required' };
    }
    return { user, error: null };
  } catch (err: any) {
    return { user: null, error: err?.message || 'Authentication failed' };
  }
}

export async function verifyOrgMembership(
  supabase: SupabaseClient,
  organizationId: string,
  userId: string,
  requiredRole: OrganizationRole = 'member'
): Promise<{ authorized: boolean; role?: OrganizationRole; error?: string }> {
  if (!organizationId || !userId) {
    return { authorized: false, error: 'Missing organization ID or user ID' };
  }

  const { data: membership, error } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .maybeSingle();

  if (error || !membership) {
    return {
      authorized: false,
      error: 'Forbidden: You are not an authorized member of this organization',
    };
  }

  const userRole = membership.role as OrganizationRole;
  const userLevel = ROLE_HIERARCHY[userRole] || 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;

  if (userLevel < requiredLevel) {
    return {
      authorized: false,
      role: userRole,
      error: `Forbidden: Requires '${requiredRole}' role or higher, but your role is '${userRole}'`,
    };
  }

  return { authorized: true, role: userRole };
}

export function validateRoleAssignment(actorRole: OrganizationRole, requestedRole: string): { valid: boolean; error?: string } {
  const allowedRoles: OrganizationRole[] = ['admin', 'member', 'viewer'];

  if (requestedRole === 'owner') {
    return {
      valid: false,
      error: 'Forbidden: Owner role cannot be assigned directly. Use dedicated owner transfer workflow.',
    };
  }

  if (!allowedRoles.includes(requestedRole as OrganizationRole)) {
    return {
      valid: false,
      error: `Invalid role '${requestedRole}'. Allowed roles: ${allowedRoles.join(', ')}`,
    };
  }

  const actorLevel = ROLE_HIERARCHY[actorRole] || 0;
  const targetLevel = ROLE_HIERARCHY[requestedRole as OrganizationRole] || 0;

  if (actorLevel <= targetLevel && actorRole !== 'owner') {
    return {
      valid: false,
      error: `Forbidden: Cannot assign a role equal to or higher than your own (${actorRole})`,
    };
  }

  return { valid: true };
}

export type AuthRole = 'system_admin' | 'owner' | 'admin' | 'enterprise_admin' | 'member' | 'viewer';

export type AuthAction =
  | 'org.read'
  | 'org.manage_members'
  | 'project.create'
  | 'project.delete'
  | 'key.create'
  | 'key.rotate'
  | 'key.revoke'
  | 'policy.read'
  | 'policy.write'
  | 'fleet.read'
  | 'fleet.manage'
  | 'billing.manage'
  | 'audit.export'
  | 'system_admin';

export interface AuthPrincipal {
  userId: string;
  organizationId?: string;
  role: AuthRole;
  isSystemAdmin?: boolean;
  isEnterpriseAdmin?: boolean;
}

export interface AuthResource {
  organizationId?: string;
  projectId?: string;
  keyId?: string;
  resourceType?: string;
  ownerId?: string;
}

export interface AuthResult {
  authorized: boolean;
  reason?: string;
  role?: AuthRole;
}

export class AuthorizationService {
  private static rolePermissions: Record<AuthRole, Set<AuthAction>> = {
    system_admin: new Set<AuthAction>([
      'org.read', 'org.manage_members', 'project.create', 'project.delete',
      'key.create', 'key.rotate', 'key.revoke', 'policy.read', 'policy.write',
      'fleet.read', 'fleet.manage', 'billing.manage', 'audit.export', 'system_admin'
    ]),
    owner: new Set<AuthAction>([
      'org.read', 'org.manage_members', 'project.create', 'project.delete',
      'key.create', 'key.rotate', 'key.revoke', 'policy.read', 'policy.write',
      'fleet.read', 'fleet.manage', 'billing.manage', 'audit.export'
    ]),
    enterprise_admin: new Set<AuthAction>([
      'org.read', 'org.manage_members', 'project.create', 'project.delete',
      'key.create', 'key.rotate', 'key.revoke', 'policy.read', 'policy.write',
      'fleet.read', 'fleet.manage', 'billing.manage', 'audit.export'
    ]),
    admin: new Set<AuthAction>([
      'org.read', 'org.manage_members', 'project.create',
      'key.create', 'key.rotate', 'key.revoke', 'policy.read', 'policy.write',
      'fleet.read', 'fleet.manage', 'audit.export'
    ]),
    member: new Set<AuthAction>([
      'org.read', 'project.create', 'key.create', 'policy.read', 'fleet.read'
    ]),
    viewer: new Set<AuthAction>([
      'org.read', 'policy.read', 'fleet.read'
    ])
  };

  /**
   * Evaluates if principal has authority to perform action on resource
   */
  public static authorize(
    principal: AuthPrincipal,
    action: AuthAction,
    resource?: AuthResource
  ): AuthResult {
    if (principal.isSystemAdmin || principal.role === 'system_admin') {
      return { authorized: true, role: 'system_admin' };
    }

    if (action === 'system_admin') {
      return { authorized: false, reason: 'Requires system_admin privileges' };
    }

    if (resource?.organizationId && principal.organizationId) {
      if (resource.organizationId !== principal.organizationId) {
        return {
          authorized: false,
          reason: `Cross-tenant access denied. Principal org ${principal.organizationId} cannot access resource org ${resource.organizationId}`
        };
      }
    }

    const allowedActions = this.rolePermissions[principal.role];
    if (!allowedActions || !allowedActions.has(action)) {
      return {
        authorized: false,
        reason: `Role '${principal.role}' is not granted permission '${action}'`,
        role: principal.role
      };
    }

    return { authorized: true, role: principal.role };
  }
}

export function authorizeRoute(
  user: User,
  action: AuthAction,
  resource?: AuthResource,
  organizationId?: string
): AuthResult {
  const isMaster =
    user.app_metadata?.role === 'master_admin' ||
    (Boolean(process.env.MASTER_ADMIN_USER_ID) && user.id === process.env.MASTER_ADMIN_USER_ID) ||
    (Boolean(process.env.MASTER_ADMIN_EMAIL) && (user.email || '').toLowerCase() === (process.env.MASTER_ADMIN_EMAIL || '').toLowerCase());

  if (isMaster) {
    return { authorized: true, role: 'system_admin' };
  }

  const role = (user.app_metadata?.role as AuthRole) || 'member';
  const principal: AuthPrincipal = {
    userId: user.id,
    organizationId: organizationId || (user.app_metadata?.organization_id as string | undefined),
    role,
    isSystemAdmin: isMaster,
    isEnterpriseAdmin: user.app_metadata?.plan === 'enterprise' || user.app_metadata?.role === 'enterprise_admin'
  };

  return AuthorizationService.authorize(principal, action, resource);
}

export async function getAuthenticatedUserWithBearer(
  req: Request,
  supabase: SupabaseClient,
  adminSupabase?: SupabaseClient
): Promise<{ user: User | null; error: string | null }> {
  try {
    const authHeader = req.headers.get('authorization');
    const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7).trim() : undefined;
    if (bearerToken && adminSupabase) {
      const { data: { user }, error: bearerErr } = await adminSupabase.auth.getUser(bearerToken);
      if (user && !bearerErr) return { user, error: null };
    }
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
      return { user: null, error: error?.message || 'Authentication required' };
    }
    return { user, error: null };
  } catch (err: any) {
    return { user: null, error: err?.message || 'Authentication failed' };
  }
}

export interface TenantAuthContext {
  user: User;
  organizationId: string;
  role: OrganizationRole;
}

export type TenantRouteHandler = (
  req: Request,
  context: TenantAuthContext,
  params?: any
) => Promise<Response>;

export function withTenantAuth(
  requiredRole: OrganizationRole,
  handler: TenantRouteHandler
) {
  return async (req: Request, routeProps?: { params?: Promise<any> | any }): Promise<Response> => {
    const rawParams = routeProps?.params;
    const params = rawParams instanceof Promise ? await rawParams : (rawParams || {});
    const orgId = params.id || params.organizationId || req.headers.get('x-organization-id');

    if (!orgId) {
      return Response.json({ error: 'Missing organization context' }, { status: 400 });
    }

    const { createClient } = await import('../utils/supabase/server');
    const supabase = await createClient();
    const { user, error: userError } = await getAuthenticatedUser(supabase);

    if (!user || userError) {
      return Response.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
    }

    const authCheck = await verifyOrgMembership(supabase, orgId, user.id, requiredRole);
    if (!authCheck.authorized) {
      return Response.json({ error: authCheck.error || 'Forbidden: Access denied' }, { status: 403 });
    }

    return handler(req, { user, organizationId: orgId, role: authCheck.role || requiredRole }, params);
  };
}

