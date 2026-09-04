/**
 * MCP Shield - Unified Security Graph
 * Step 3 Roadmap - Section 5, Section 6 & Milestone D
 *
 * Unifies tools, identities, capabilities, data assets, destinations, and attack paths
 * into a single unified Security Graph with pathfinding and blast radius algorithms.
 */

export type GraphNodeType = 'tool' | 'capability' | 'asset' | 'destination' | 'action' | 'identity';

export type GraphEdgeRelation =
  | 'CAN_READ'
  | 'CAN_WRITE'
  | 'CAN_EXECUTE'
  | 'CAN_CONTACT'
  | 'CAN_INVOKE'
  | 'DERIVED_FROM'
  | 'CHANGED_FROM';

export interface AttackGraphNode {
  type: GraphNodeType;
  id: string;
  name?: string;
  properties?: Record<string, any>;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  relation: GraphEdgeRelation;
  weight?: number; // 1.0 default
  metadata?: Record<string, any>;
}

export interface AttackPathAnalysisResult {
  pathExists: boolean;
  path: string[]; // sequence of node IDs
  length: number;
  riskScore: number; // 0 to 100
  requiredCapabilities: string[];
  sensitiveAssetsTouched: string[];
  externalDestinations: string[];
  policyViolations: string[];
  blastRadiusScore: number; // 0.0 to 1.0
  remediationRecommendation?: string;
}

export class SecurityGraph {
  private nodes = new Map<string, AttackGraphNode>();
  private adjacency = new Map<string, AttackGraphEdge[]>(); // source -> edges
  private reverseAdjacency = new Map<string, AttackGraphEdge[]>(); // target -> edges

  public addNode(node: AttackGraphNode): void {
    this.nodes.set(node.id, node);
    if (!this.adjacency.has(node.id)) this.adjacency.set(node.id, []);
    if (!this.reverseAdjacency.has(node.id)) this.reverseAdjacency.set(node.id, []);
  }

  public addEdge(edge: AttackGraphEdge): void {
    if (!this.nodes.has(edge.source)) {
      this.addNode({ type: 'tool', id: edge.source });
    }
    if (!this.nodes.has(edge.target)) {
      this.addNode({ type: 'tool', id: edge.target });
    }

    const edges = this.adjacency.get(edge.source) || [];
    edges.push(edge);
    this.adjacency.set(edge.source, edges);

    const revEdges = this.reverseAdjacency.get(edge.target) || [];
    revEdges.push(edge);
    this.reverseAdjacency.set(edge.target, revEdges);
  }

  public getNode(id: string): AttackGraphNode | undefined {
    return this.nodes.get(id);
  }

  public getAllNodes(): AttackGraphNode[] {
    return Array.from(this.nodes.values());
  }

  public getEdgesFrom(nodeId: string): AttackGraphEdge[] {
    return this.adjacency.get(nodeId) || [];
  }

  /**
   * Calculates Dijkstra / BFS minimum path between source and target
   */
  public findMinimumAttackPath(startNodeId: string, endNodeId: string): string[] | null {
    if (!this.nodes.has(startNodeId) || !this.nodes.has(endNodeId)) return null;
    if (startNodeId === endNodeId) return [startNodeId];

    const queue: Array<{ id: string; path: string[] }> = [{ id: startNodeId, path: [startNodeId] }];
    const visited = new Set<string>([startNodeId]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      const neighbors = this.adjacency.get(current.id) || [];

      for (const edge of neighbors) {
        if (edge.target === endNodeId) {
          return [...current.path, edge.target];
        }

        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push({
            id: edge.target,
            path: [...current.path, edge.target]
          });
        }
      }
    }

    return null;
  }

  /**
   * Calculates blast radius: fraction of nodes transitively reachable from a start node
   */
  public calculateBlastRadius(startNodeId: string): { reachableCount: number; reachableRatio: number; nodes: string[] } {
    if (!this.nodes.has(startNodeId)) {
      return { reachableCount: 0, reachableRatio: 0, nodes: [] };
    }

    const visited = new Set<string>();
    const queue: string[] = [startNodeId];

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const edges = this.adjacency.get(curr) || [];
      for (const e of edges) {
        if (!visited.has(e.target)) {
          visited.add(e.target);
          queue.push(e.target);
        }
      }
    }

    const totalNodes = Math.max(1, this.nodes.size - 1);
    const reachableCount = visited.size;
    const reachableRatio = Math.round((reachableCount / totalNodes) * 100) / 100;

    return {
      reachableCount,
      reachableRatio,
      nodes: Array.from(visited)
    };
  }

  /**
   * Comprehensive attack path risk evaluation from sensitive asset to destination
   */
  public evaluateAttackPath(startNodeId: string, endNodeId: string): AttackPathAnalysisResult {
    const path = this.findMinimumAttackPath(startNodeId, endNodeId);
    if (!path) {
      return {
        pathExists: false,
        path: [],
        length: 0,
        riskScore: 0,
        requiredCapabilities: [],
        sensitiveAssetsTouched: [],
        externalDestinations: [],
        policyViolations: [],
        blastRadiusScore: 0
      };
    }

    const requiredCaps: Set<string> = new Set();
    const sensitiveAssets: Set<string> = new Set();
    const externalDests: Set<string> = new Set();
    const violations: string[] = [];

    for (const nodeId of path) {
      const node = this.nodes.get(nodeId);
      if (!node) continue;

      if (node.type === 'asset' || /credential|secret|key|vault|passwd|database/i.test(nodeId)) {
        sensitiveAssets.add(nodeId);
      }
      if (node.type === 'destination' || /external|internet|webhook|pastebin|cloud/i.test(nodeId)) {
        externalDests.add(nodeId);
      }
      if (node.type === 'capability') {
        requiredCaps.add(nodeId);
      }
      if (node.properties?.capabilities && Array.isArray(node.properties.capabilities)) {
        for (const c of node.properties.capabilities) requiredCaps.add(c);
      }
    }

    // Identify policy violations
    if (sensitiveAssets.size > 0 && externalDests.size > 0) {
      violations.push('Critical Exfiltration Path: Direct reachability between sensitive asset and external egress destination');
    }
    if (requiredCaps.has('filesystemRead') && requiredCaps.has('networkAccess')) {
      violations.push('High-Risk Capability Composition: read capability composable with network egress in single chain');
    }

    const blastRadius = this.calculateBlastRadius(startNodeId);

    // Compute risk score (0-100)
    let riskScore = 30;
    if (sensitiveAssets.size > 0) riskScore += 30;
    if (externalDests.size > 0) riskScore += 30;
    if (path.length <= 4) riskScore += 10; // Shorter paths are more dangerous

    riskScore = Math.min(100, riskScore);

    let remediationRecommendation: string | undefined;
    if (sensitiveAssets.size > 0 && externalDests.size > 0) {
      // Find intermediate bridge node
      const bridgeNode = path.length > 2 ? path[Math.floor(path.length / 2)] : path[0];
      remediationRecommendation = `Sever exfiltration path: revoke network.egress from bridge node '${bridgeNode}' or enforce secret-vault isolation on '${Array.from(sensitiveAssets)[0]}'`;
    }

    return {
      pathExists: true,
      path,
      length: path.length,
      riskScore,
      requiredCapabilities: Array.from(requiredCaps),
      sensitiveAssetsTouched: Array.from(sensitiveAssets),
      externalDestinations: Array.from(externalDests),
      policyViolations: violations,
      blastRadiusScore: blastRadius.reachableRatio,
      remediationRecommendation
    };
  }
}
