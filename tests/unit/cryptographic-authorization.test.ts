import * as crypto from 'crypto';
import { AuthorizationModule, ApprovalPayload } from '../../src/security/authorization';

describe('AuthorizationModule Cryptographic Quorum (Roadmap Section 5.7)', () => {
  let authModule: AuthorizationModule;
  const orgId = 'org-corp-1';

  // Approver 1 keys
  const key1 = 'secret-signing-key-approver-1';
  // Approver 2 keys
  const key2 = 'secret-signing-key-approver-2';

  beforeEach(() => {
    authModule = new AuthorizationModule();
    authModule.registerApprover('alice', key1, orgId);
    authModule.registerApprover('bob', key2, orgId);
    authModule.registerApprover('eve', 'eve-key', 'org-evil-corp');
  });

  it('successfully reaches APPROVED status with 2 valid signatures (Four-Eyes principle)', () => {
    const action = 'system:reconfigure_firewall';
    const reqId = authModule.initiateQuorumApproval(action, orgId);

    // Alice approves
    const payloadAlice: ApprovalPayload = {
      requestId: reqId,
      approverId: 'alice',
      organizationId: orgId,
      action,
      nonce: crypto.randomBytes(16).toString('hex'),
      expiresAt: Date.now() + 60000
    };
    const sigAlice = crypto
      .createHmac('sha256', key1)
      .update(JSON.stringify(payloadAlice))
      .digest('hex');

    authModule.recordApproval(reqId, 'alice', sigAlice, payloadAlice);
    expect(authModule.getApprovalStatus(reqId)?.status).toBe('PENDING');

    // Bob approves
    const payloadBob: ApprovalPayload = {
      requestId: reqId,
      approverId: 'bob',
      organizationId: orgId,
      action,
      nonce: crypto.randomBytes(16).toString('hex'),
      expiresAt: Date.now() + 60000
    };
    const sigBob = crypto
      .createHmac('sha256', key2)
      .update(JSON.stringify(payloadBob))
      .digest('hex');

    authModule.recordApproval(reqId, 'bob', sigBob, payloadBob);
    expect(authModule.getApprovalStatus(reqId)?.status).toBe('APPROVED');
  });

  it('rejects invalid cryptographic signatures', () => {
    const reqId = authModule.initiateQuorumApproval('deploy:production', orgId);
    const payload: ApprovalPayload = {
      requestId: reqId,
      approverId: 'alice',
      organizationId: orgId,
      action: 'deploy:production',
      nonce: crypto.randomBytes(16).toString('hex'),
      expiresAt: Date.now() + 60000
    };
    const bogusSig = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

    expect(() => {
      authModule.recordApproval(reqId, 'alice', bogusSig, payload);
    }).toThrow(/Cryptographic verification failed/);
  });

  it('prevents replay attacks using consumed nonces', () => {
    const reqId1 = authModule.initiateQuorumApproval('action-1', orgId);
    const nonce = 'shared-reused-nonce-12345';
    const payload1: ApprovalPayload = {
      requestId: reqId1,
      approverId: 'alice',
      organizationId: orgId,
      action: 'action-1',
      nonce,
      expiresAt: Date.now() + 60000
    };
    const sig1 = crypto.createHmac('sha256', key1).update(JSON.stringify(payload1)).digest('hex');
    authModule.recordApproval(reqId1, 'alice', sig1, payload1);

    const reqId2 = authModule.initiateQuorumApproval('action-2', orgId);
    const payload2: ApprovalPayload = {
      requestId: reqId2,
      approverId: 'alice',
      organizationId: orgId,
      action: 'action-2',
      nonce, // Same nonce
      expiresAt: Date.now() + 60000
    };
    const sig2 = crypto.createHmac('sha256', key1).update(JSON.stringify(payload2)).digest('hex');

    expect(() => {
      authModule.recordApproval(reqId2, 'alice', sig2, payload2);
    }).toThrow(/Replay attack detected/);
  });

  it('rejects cross-tenant approvers', () => {
    const reqId = authModule.initiateQuorumApproval('action-tenant', orgId);
    const payload: ApprovalPayload = {
      requestId: reqId,
      approverId: 'eve',
      organizationId: 'org-evil-corp',
      action: 'action-tenant',
      nonce: crypto.randomBytes(16).toString('hex'),
      expiresAt: Date.now() + 60000
    };
    const sigEve = crypto.createHmac('sha256', 'eve-key').update(JSON.stringify(payload)).digest('hex');

    expect(() => {
      authModule.recordApproval(reqId, 'eve', sigEve, payload);
    }).toThrow(/Cross-tenant approval rejected/);
  });
});
