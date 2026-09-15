import {
  SqliteDurableAuditSink,
  HumanOversightService
} from '../../src';
import { AuditComplianceLedger } from '../../src/security/audit-ledger';

describe('Three Mandatory Production Remediations Suite (Blueprint Section 9)', () => {
  describe('Remediation 1: FIPS 140-3 SHA3-256 Alignment', () => {
    it('creates and verifies Merkle audit ledgers using SHA3-256', () => {
      const ledger = new AuditComplianceLedger({
        signingKey: 'fips-test-key-32bytes-secret12345',
        algorithm: 'sha3-256'
      });

      const e1 = ledger.logEvent('admin', 'mcp.tool_call', { tool: 'bash' });
      const e2 = ledger.logEvent('admin', 'mcp.tool_call', { tool: 'curl' });

      expect(e1.algorithm).toBe('sha3-256');
      expect(e2.algorithm).toBe('sha3-256');
      expect(e1.signature.length).toBe(64); // 32 bytes hex

      const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(
        ledger.getLedger(),
        (id: string) => ledger.getKey(id)
      );
      expect(report.valid).toBe(true);
      expect(report.verifiedCount).toBe(2);
      expect(report.computedMerkleRoot).toBeDefined();
    });
  });

  describe('Remediation 2: EU AI Act Art. 14 Human Oversight Service', () => {
    it('enqueues high-risk decisions and enforces four-eyes quorum approval', () => {
      const oversight = new HumanOversightService({ defaultQuorum: 2, ttlMs: 60000 });

      const mockDecision = {
        requestId: 'req_oversight_01',
        action: 'BLOCK',
        riskScore: 0.92,
        detectorIds: ['ML_FUSION', 'AST_INJECTION'],
        reasons: ['Suspicious multi-turn script mutation']
      };

      const record = oversight.submitForReview(mockDecision);
      expect(record.status).toBe('PENDING_REVIEW');
      expect(record.requiredQuorum).toBe(2);

      // Reviewer 1 approves: quorum not yet satisfied
      const verdict1 = oversight.approve(record.id, 'reviewer-alpha@corp.local', 'Looks safe for this build');
      expect(verdict1.allowed).toBe(false);
      expect(verdict1.quorumSatisfied).toBe(false);
      expect(verdict1.approvalsCount).toBe(1);

      // Reviewer 2 approves: quorum satisfied -> status APPROVED
      const verdict2 = oversight.approve(record.id, 'reviewer-beta@corp.local', 'Verified clean');
      expect(verdict2.allowed).toBe(true);
      expect(verdict2.quorumSatisfied).toBe(true);
      expect(verdict2.approvalsCount).toBe(2);
      expect(verdict2.status).toBe('APPROVED');
    });

    it('rejects decisions upholding block verdict', () => {
      const oversight = new HumanOversightService();
      const mockDecision = {
        requestId: 'req_oversight_02',
        action: 'QUARANTINE',
        riskScore: 0.88,
        detectorIds: [],
        reasons: ['Unverified binary download']
      };

      const record = oversight.submitForReview(mockDecision);
      const verdict = oversight.reject(record.id, 'admin@corp.local', 'Confirmed malicious script');
      expect(verdict.allowed).toBe(false);
      expect(verdict.status).toBe('REJECTED');
    });
  });

  describe('Remediation 3: Persistent SQLite WAL Audit Sink (SOC 2 CC7.2)', () => {
    it('persists audit events directly to an immutable SQLite WAL sink', () => {
      const sink = new SqliteDurableAuditSink(':memory:');
      const ledger = new AuditComplianceLedger({
        signingKey: 'sqlite-test-key-12345',
        sink,
        algorithm: 'sha3-256'
      });

      ledger.logEvent('system', 'init', { status: 'boot' });
      ledger.logEvent('agent', 'read_file', { path: '/src/main.ts' });

      sink.flush();
      const loadedEvents = sink.readEvents();

      expect(loadedEvents.length).toBe(2);
      expect(loadedEvents[0].sequenceNumber).toBe(1);
      expect(loadedEvents[1].sequenceNumber).toBe(2);
      expect(loadedEvents[0].actor).toBe('system');
      expect(loadedEvents[1].actor).toBe('agent');
      expect(loadedEvents[0].algorithm).toBe('sha3-256');

      sink.close();
    });
  });
});
