import { AuthorizationService, AuthPrincipal } from '../../../src/security/authz/authorization-service';

describe('Route-Level Authorization Matrix (Roadmap Section 8.3)', () => {
  const orgA = 'org-tenant-alpha';
  const orgB = 'org-tenant-beta';

  const principals: Record<string, AuthPrincipal> = {
    viewer: { userId: 'u-viewer', organizationId: orgA, role: 'viewer' },
    member: { userId: 'u-member', organizationId: orgA, role: 'member' },
    admin: { userId: 'u-admin', organizationId: orgA, role: 'admin' },
    owner: { userId: 'u-owner', organizationId: orgA, role: 'owner' },
    enterpriseAdmin: { userId: 'u-ent', organizationId: orgA, role: 'enterprise_admin', isEnterpriseAdmin: true },
    systemAdmin: { userId: 'u-sys', organizationId: orgA, role: 'system_admin', isSystemAdmin: true },
    crossOrgAttacker: { userId: 'u-evil', organizationId: orgB, role: 'admin' }
  };

  it('verifies viewer read-only permissions and denies mutations', () => {
    const read = AuthorizationService.authorize(principals.viewer, 'org.read', { organizationId: orgA });
    expect(read.authorized).toBe(true);

    const keyCreate = AuthorizationService.authorize(principals.viewer, 'key.create', { organizationId: orgA });
    expect(keyCreate.authorized).toBe(false);

    const billing = AuthorizationService.authorize(principals.viewer, 'billing.manage', { organizationId: orgA });
    expect(billing.authorized).toBe(false);
  });

  it('verifies member can create keys and read policies but cannot manage members', () => {
    const keyCreate = AuthorizationService.authorize(principals.member, 'key.create', { organizationId: orgA });
    expect(keyCreate.authorized).toBe(true);

    const manageMembers = AuthorizationService.authorize(principals.member, 'org.manage_members', { organizationId: orgA });
    expect(manageMembers.authorized).toBe(false);
  });

  it('verifies admin can manage keys, policies, and fleet but not billing', () => {
    const keyRotate = AuthorizationService.authorize(principals.admin, 'key.rotate', { organizationId: orgA });
    expect(keyRotate.authorized).toBe(true);

    const policyWrite = AuthorizationService.authorize(principals.admin, 'policy.write', { organizationId: orgA });
    expect(policyWrite.authorized).toBe(true);

    const billing = AuthorizationService.authorize(principals.admin, 'billing.manage', { organizationId: orgA });
    expect(billing.authorized).toBe(false);
  });

  it('verifies owner can manage all organization aspects including billing', () => {
    const billing = AuthorizationService.authorize(principals.owner, 'billing.manage', { organizationId: orgA });
    expect(billing.authorized).toBe(true);

    const keyRevoke = AuthorizationService.authorize(principals.owner, 'key.revoke', { organizationId: orgA });
    expect(keyRevoke.authorized).toBe(true);
  });

  it('verifies system admin possesses universal access', () => {
    const sys = AuthorizationService.authorize(principals.systemAdmin, 'system_admin');
    expect(sys.authorized).toBe(true);

    const crossOrgBypass = AuthorizationService.authorize(principals.systemAdmin, 'key.rotate', { organizationId: orgB });
    expect(crossOrgBypass.authorized).toBe(true);
  });

  it('denies cross-organization attacker access to another tenant resources', () => {
    const crossAccess = AuthorizationService.authorize(principals.crossOrgAttacker, 'org.read', { organizationId: orgA });
    expect(crossAccess.authorized).toBe(false);
    expect(crossAccess.reason).toContain('Cross-tenant access denied');

    const crossMutate = AuthorizationService.authorize(principals.crossOrgAttacker, 'key.create', { organizationId: orgA });
    expect(crossMutate.authorized).toBe(false);
  });
});
