import { SecurityGraph } from '../../src/security/graph/security-graph';

describe('Security Graph & Attack Path Engine (Roadmap Section 5 & 6)', () => {
  it('constructs multi-node security graph and finds minimum attack path', () => {
    const graph = new SecurityGraph();

    // Nodes
    graph.addNode({ type: 'asset', id: 'credential:aws_keys', name: 'AWS Credentials' });
    graph.addNode({ type: 'tool', id: 'tool:reader', properties: { capabilities: ['filesystemRead'] } });
    graph.addNode({ type: 'tool', id: 'tool:transformer', properties: { capabilities: ['filesystemWrite'] } });
    graph.addNode({ type: 'tool', id: 'tool:egress_uploader', properties: { capabilities: ['networkAccess'] } });
    graph.addNode({ type: 'destination', id: 'dest:attacker_s3', name: 'Untrusted S3 Bucket' });

    // Edges
    graph.addEdge({ source: 'credential:aws_keys', target: 'tool:reader', relation: 'CAN_READ' });
    graph.addEdge({ source: 'tool:reader', target: 'tool:transformer', relation: 'CAN_INVOKE' });
    graph.addEdge({ source: 'tool:transformer', target: 'tool:egress_uploader', relation: 'CAN_INVOKE' });
    graph.addEdge({ source: 'tool:egress_uploader', target: 'dest:attacker_s3', relation: 'CAN_CONTACT' });

    const path = graph.findMinimumAttackPath('credential:aws_keys', 'dest:attacker_s3');
    expect(path).toEqual([
      'credential:aws_keys',
      'tool:reader',
      'tool:transformer',
      'tool:egress_uploader',
      'dest:attacker_s3'
    ]);

    const analysis = graph.evaluateAttackPath('credential:aws_keys', 'dest:attacker_s3');
    expect(analysis.pathExists).toBe(true);
    expect(analysis.riskScore).toBeGreaterThanOrEqual(80);
    expect(analysis.sensitiveAssetsTouched).toContain('credential:aws_keys');
    expect(analysis.externalDestinations).toContain('dest:attacker_s3');
    expect(analysis.policyViolations.length).toBeGreaterThan(0);
    expect(analysis.remediationRecommendation).toBeDefined();
  });

  it('calculates blast radius ratio for compromised nodes', () => {
    const graph = new SecurityGraph();
    graph.addNode({ type: 'tool', id: 'node_a' });
    graph.addNode({ type: 'tool', id: 'node_b' });
    graph.addNode({ type: 'tool', id: 'node_c' });
    graph.addNode({ type: 'tool', id: 'node_isolated' });

    graph.addEdge({ source: 'node_a', target: 'node_b', relation: 'CAN_INVOKE' });
    graph.addEdge({ source: 'node_b', target: 'node_c', relation: 'CAN_INVOKE' });

    const blastA = graph.calculateBlastRadius('node_a');
    expect(blastA.reachableCount).toBe(2); // b and c
    expect(blastA.reachableRatio).toBeGreaterThan(0.5);

    const blastIsolated = graph.calculateBlastRadius('node_isolated');
    expect(blastIsolated.reachableCount).toBe(0);
  });
});
