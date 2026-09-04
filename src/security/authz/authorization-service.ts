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
    // 1. System admin check
    if (principal.isSystemAdmin || principal.role === 'system_admin') {
      return { authorized: true, role: 'system_admin' };
    }

    if (action === 'system_admin') {
      return { authorized: false, reason: 'Requires system_admin privileges' };
    }

    // 2. Tenant isolation check: if resource specifies organizationId, principal must belong to that organization
    if (resource?.organizationId && principal.organizationId) {
      if (resource.organizationId !== principal.organizationId) {
        return {
          authorized: false,
          reason: `Cross-tenant access denied. Principal org ${principal.organizationId} cannot access resource org ${resource.organizationId}`
        };
      }
    }

    // 3. Role-based permission evaluation
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
