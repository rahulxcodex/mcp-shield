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

export interface SupabaseUserSession {
  id: string;
  email?: string;
  app_metadata?: {
    role?: string;
    organization_id?: string;
    plan?: string;
  };
  user_metadata?: Record<string, any>;
}

export function principalFromSession(
  user: SupabaseUserSession,
  orgIdHeader?: string
): AuthPrincipal {
  const isMasterAdmin =
    user.app_metadata?.role === 'master_admin' ||
    user.id === process.env.MASTER_ADMIN_USER_ID;

  const isEnterpriseAdmin =
    user.app_metadata?.role === 'enterprise_admin' ||
    user.app_metadata?.plan === 'enterprise';

  let role: AuthRole = 'member';
  if (isMasterAdmin) {
    role = 'system_admin';
  } else if (isEnterpriseAdmin) {
    role = 'enterprise_admin';
  } else if (user.app_metadata?.role === 'owner') {
    role = 'owner';
  } else if (user.app_metadata?.role === 'admin') {
    role = 'admin';
  } else if (user.app_metadata?.role === 'viewer') {
    role = 'viewer';
  }

  const organizationId =
    orgIdHeader ||
    user.app_metadata?.organization_id ||
    `org-${user.id.substring(0, 8)}`;

  return {
    userId: user.id,
    organizationId,
    role,
    isSystemAdmin: isMasterAdmin,
    isEnterpriseAdmin
  };
}

export function authorizeRoute(
  user: SupabaseUserSession,
  action: AuthAction,
  resource?: AuthResource,
  orgIdHeader?: string
): AuthResult {
  const principal = principalFromSession(user, orgIdHeader);
  return AuthorizationService.authorize(principal, action, resource);
}
