import { ProvenanceManager } from '../../src/security/provenance/provenance-manager';

describe('ProvenanceManager (Roadmap Section 6.4)', () => {
  it('registers package provenance and evaluates verified matches', () => {
    const mgr = new ProvenanceManager();
    const pkgId = '@org/mcp-database-tool';
    const binaryDigest = 'sha256:11112222333344445555666677778888';

    mgr.registerOrUpdateProvenance({
      packageIdentity: pkgId,
      publisherIdentity: 'Verified Dev Team',
      binaryDigest,
      signatureVerified: true,
      schemaHash: 'schema-hash-1'
    });

    const decision = mgr.evaluateProvenance(pkgId, binaryDigest, 'schema-hash-1');
    expect(decision.binaryHashVerified).toBe(true);
    expect(decision.signatureVerified).toBe(true);
    expect(decision.anomalyDetected).toBe(false);
    expect(decision.trustScore).toBeGreaterThanOrEqual(0.8);
  });

  it('flags anomaly on binary digest mismatch (binary replacement/tampering)', () => {
    const mgr = new ProvenanceManager();
    const pkgId = '@org/mcp-filesystem';

    mgr.registerOrUpdateProvenance({
      packageIdentity: pkgId,
      publisherIdentity: 'Core Tools',
      binaryDigest: 'sha256:original',
      signatureVerified: true
    });

    const decision = mgr.evaluateProvenance(pkgId, 'sha256:tampered_binary');
    expect(decision.binaryHashVerified).toBe(false);
    expect(decision.anomalyDetected).toBe(true);
    expect(decision.trustScore).toBeLessThanOrEqual(0.3);
    expect(decision.notes?.[0]).toContain('Binary digest mismatch');
  });

  it('penalizes trust score when security incidents are logged', () => {
    const mgr = new ProvenanceManager();
    const pkgId = '@org/mcp-web-fetcher';

    mgr.registerOrUpdateProvenance({
      packageIdentity: pkgId,
      publisherIdentity: 'External Partner',
      binaryDigest: 'hash1',
      initialTrustScore: 0.8
    });

    mgr.recordIncident(pkgId, 'Attempted SSRF to 169.254.169.254');
    const record = mgr.getRecord(pkgId);
    expect(record?.incidentCount).toBe(1);
    expect(record?.trustScore).toBe(0.55);

    const decision = mgr.evaluateProvenance(pkgId);
    expect(decision.notes?.some((n) => n.includes('1 recorded security incidents'))).toBe(true);
  });
});
