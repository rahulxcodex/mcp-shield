import { AuditComplianceLedger, MemoryAuditSink } from '../../src/security/audit-ledger';

describe('AuditComplianceLedger (Roadmap Section 5.6)', () => {
  it('logs events with monotonic sequence numbers and valid chaining', () => {
    const sink = new MemoryAuditSink();
    const ledger = new AuditComplianceLedger({ signingKey: 'super-secret-key-1', sink });

    const e1 = ledger.logEvent('user-1', 'mcp.tool_call', { tool: 'bash', cmd: 'ls' });
    const e2 = ledger.logEvent('user-2', 'mcp.tool_call', { tool: 'fetch', url: 'https://example.com' });
    const e3 = ledger.logEvent('user-1', 'mcp.resource_read', { uri: 'file:///tmp/data' });

    expect(e1.sequenceNumber).toBe(1);
    expect(e2.sequenceNumber).toBe(2);
    expect(e3.sequenceNumber).toBe(3);

    expect(e2.previousHash).toBe(e1.signature);
    expect(e3.previousHash).toBe(e2.signature);

    const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(
      ledger.getLedger(),
      (id) => ledger.getKey(id)
    );

    expect(report.valid).toBe(true);
    expect(report.verifiedCount).toBe(3);
    expect(report.computedMerkleRoot).toBeDefined();
  });

  it('detects tampering when an event payload is modified', () => {
    const ledger = new AuditComplianceLedger({ signingKey: 'tamper-test-key' });
    ledger.logEvent('actor-a', 'action-1', 'payload-1');
    ledger.logEvent('actor-b', 'action-2', 'payload-2');

    const events = ledger.getLedger();
    // Tamper with payload of event 2
    events[1].payloadHash = 'tampered-hash-value-0000000000000000000000000000000000000000000000';

    const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(events, (id) => ledger.getKey(id));
    expect(report.valid).toBe(false);
    expect(report.tamperedIndex).toBe(1);
    expect(report.reason).toContain('Signature mismatch');
  });

  it('detects tampering when events are reordered or omitted', () => {
    const ledger = new AuditComplianceLedger({ signingKey: 'reorder-key' });
    ledger.logEvent('actor-1', 'action-1', 'p1');
    ledger.logEvent('actor-2', 'action-2', 'p2');
    ledger.logEvent('actor-3', 'action-3', 'p3');

    const events = ledger.getLedger();
    // Swap event 1 and event 2
    const swapped = [events[0], events[2], events[1]];

    const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(swapped, (id) => ledger.getKey(id));
    expect(report.valid).toBe(false);
    expect(report.tamperedIndex).toBe(1);
  });

  it('supports key rotation and validates multi-key chains', () => {
    const ledger = new AuditComplianceLedger({ signingKey: 'key-1', keyId: 'k1' });
    ledger.logEvent('actor', 'step1', 'data1');

    ledger.rotateKey('k2', 'key-2');
    ledger.logEvent('actor', 'step2', 'data2');

    const events = ledger.getLedger();
    expect(events[0].keyId).toBe('k1');
    expect(events[1].keyId).toBe('k2');

    const report = AuditComplianceLedger.verifyAuditLedgerIntegrity(events, (id) => ledger.getKey(id));
    expect(report.valid).toBe(true);
    expect(report.verifiedCount).toBe(2);
  });
});
