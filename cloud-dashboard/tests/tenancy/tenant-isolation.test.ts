import { AuthorizationService } from '../../../src/security/authz/authorization-service';

describe('Multi-Tenant Isolation Invariants (Roadmap Section 8.4)', () => {
  const tenantAlpha = {
    userId: 'user-alice-alpha',
    organizationId: 'org-alpha',
    role: 'owner' as const
  };

  const tenantBeta = {
    userId: 'user-bob-beta',
    organizationId: 'org-beta',
    role: 'admin' as const
  };

  it('strictly prevents Tenant Alpha from reading Tenant Beta audit logs or fleet', () => {
    const auditExport = AuthorizationService.authorize(tenantAlpha, 'audit.export', {
      organizationId: 'org-beta',
      resourceType: 'audit_log'
    });
    expect(auditExport.authorized).toBe(false);
    expect(auditExport.reason).toContain('Cross-tenant access denied');

    const fleetRead = AuthorizationService.authorize(tenantAlpha, 'fleet.read', {
      organizationId: 'org-beta',
      resourceType: 'fleet_device'
    });
    expect(fleetRead.authorized).toBe(false);
  });

  it('strictly prevents Tenant Beta from rotating or revoking Tenant Alpha API keys', () => {
    const keyRotate = AuthorizationService.authorize(tenantBeta, 'key.rotate', {
      organizationId: 'org-alpha',
      keyId: 'key-alpha-999'
    });
    expect(keyRotate.authorized).toBe(false);
    expect(keyRotate.reason).toContain('Cross-tenant access denied');

    const keyRevoke = AuthorizationService.authorize(tenantBeta, 'key.revoke', {
      organizationId: 'org-alpha',
      keyId: 'key-alpha-999'
    });
    expect(keyRevoke.authorized).toBe(false);
  });

  it('prevents cross-tenant project and policy tampering', () => {
    const policyWrite = AuthorizationService.authorize(tenantBeta, 'policy.write', {
      organizationId: 'org-alpha',
      projectId: 'proj-alpha-core'
    });
    expect(policyWrite.authorized).toBe(false);

    const projDelete = AuthorizationService.authorize(tenantAlpha, 'project.delete', {
      organizationId: 'org-beta',
      projectId: 'proj-beta-core'
    });
    expect(projDelete.authorized).toBe(false);
  });
});
