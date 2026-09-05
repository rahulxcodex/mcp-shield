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

export class PriorityQueue<T> {
  private heap: Array<{ item: T; priority: number }> = [];

  public push(item: T, priority: number): void {
    this.heap.push({ item, priority });
    this.bubbleUp(this.heap.length - 1);
  }

  public pop(): T | undefined {
    if (this.heap.length === 0) return undefined;
    const top = this.heap[0].item;
    const bottom = this.heap.pop()!;
    if (this.heap.length > 0) {
      this.heap[0] = bottom;
      this.bubbleDown(0);
    }
    return top;
  }

  public get size(): number {
    return this.heap.length;
  }

  private bubbleUp(idx: number): void {
    while (idx > 0) {
      const parentIdx = (idx - 1) >> 1;
      if (this.heap[idx].priority < this.heap[parentIdx].priority) {
        const tmp = this.heap[idx];
        this.heap[idx] = this.heap[parentIdx];
        this.heap[parentIdx] = tmp;
        idx = parentIdx;
      } else {
        break;
      }
    }
  }

  private bubbleDown(idx: number): void {
    const len = this.heap.length;
    while (true) {
      let smallest = idx;
      const left = (idx << 1) + 1;
      const right = left + 1;
      if (left < len && this.heap[left].priority < this.heap[smallest].priority) {
        smallest = left;
      }
      if (right < len && this.heap[right].priority < this.heap[smallest].priority) {
        smallest = right;
      }
      if (smallest !== idx) {
        const tmp = this.heap[idx];
        this.heap[idx] = this.heap[smallest];
        this.heap[smallest] = tmp;
        idx = smallest;
      } else {
        break;
      }
    }
  }
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
   * Calculates Dijkstra / BFS minimum-cost attack path between source and target.
   * Utilizes PriorityQueue min-heap when weighted edges are present, with parent-pointer
   * backtracking to achieve O(V + E log V) complexity without path array cloning.
   */
  public findMinimumAttackPath(startNodeId: string, endNodeId: string): string[] | null {
    if (!this.nodes.has(startNodeId) || !this.nodes.has(endNodeId)) return null;
    if (startNodeId === endNodeId) return [startNodeId];

    // Check if graph contains non-default edge weights
    let hasCustomWeights = false;
    for (const edgeList of this.adjacency.values()) {
      if (edgeList.some(e => typeof e.weight === 'number' && e.weight !== 1.0)) {
        hasCustomWeights = true;
        break;
      }
    }

    const parentMap = new Map<string, string>();

    if (hasCustomWeights) {
      // Dijkstra with Min-Heap Priority Queue
      const pq = new PriorityQueue<string>();
      const dist = new Map<string, number>();
      dist.set(startNodeId, 0);
      pq.push(startNodeId, 0);

      while (pq.size > 0) {
        const current = pq.pop()!;
        if (current === endNodeId) break;

        const currentDist = dist.get(current) ?? Infinity;
        const neighbors = this.adjacency.get(current) || [];

        for (const edge of neighbors) {
          const weight = typeof edge.weight === 'number' ? Math.max(0.01, edge.weight) : 1.0;
          const newDist = currentDist + weight;
          if (newDist < (dist.get(edge.target) ?? Infinity)) {
            dist.set(edge.target, newDist);
            parentMap.set(edge.target, current);
            pq.push(edge.target, newDist);
          }
        }
      }
    } else {
      // High-performance BFS with O(1) two-pointer queue (no array.shift() overhead)
      const queue: string[] = [startNodeId];
      let head = 0;
      const visited = new Set<string>([startNodeId]);
      let reached = false;

      while (head < queue.length) {
        const current = queue[head++];
        if (current === endNodeId) {
          reached = true;
          break;
        }

        const neighbors = this.adjacency.get(current) || [];
        for (const edge of neighbors) {
          if (!visited.has(edge.target)) {
            visited.add(edge.target);
            parentMap.set(edge.target, current);
            if (edge.target === endNodeId) {
              reached = true;
              break;
            }
            queue.push(edge.target);
          }
        }
        if (reached) break;
      }
    }

    if (!parentMap.has(endNodeId)) return null;

    // Backtrack path in O(L) time
    const path: string[] = [endNodeId];
    let curr = endNodeId;
    while (curr !== startNodeId) {
      const parent = parentMap.get(curr);
      if (!parent) return null;
      path.push(parent);
      curr = parent;
    }
    return path.reverse();
  }

  /**
   * Calculates blast radius: fraction of nodes transitively reachable from a start node.
   * Uses high-performance two-pointer queue traversal with O(1) dequeues.
   */
  public calculateBlastRadius(startNodeId: string): { reachableCount: number; reachableRatio: number; nodes: string[] } {
    if (!this.nodes.has(startNodeId)) {
      return { reachableCount: 0, reachableRatio: 0, nodes: [] };
    }

    const visited = new Set<string>();
    const queue: string[] = [startNodeId];
    let head = 0;

    while (head < queue.length) {
      const curr = queue[head++];
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
      // Find mathematically optimal articulation bridge node
      const bridgeNode = this.findOptimalCutNode(path, startNodeId, endNodeId);
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

  /**
   * Identifies the optimal articulation / cut vertex along an attack path whose removal
   * severs reachability between source asset and destination sink.
   */
  public findOptimalCutNode(path: string[], startNodeId: string, endNodeId: string): string {
    if (path.length <= 2) return path[0];

    const candidates = path.slice(1, -1);
    for (const candidate of candidates) {
      const reachable = this.checkReachabilityExcluding(startNodeId, endNodeId, candidate);
      if (!reachable) {
        return candidate;
      }
    }

    let bestNode = candidates[Math.floor(candidates.length / 2)];
    let maxDegree = -1;
    for (const candidate of candidates) {
      const degree = (this.adjacency.get(candidate)?.length || 0) + (this.reverseAdjacency.get(candidate)?.length || 0);
      if (degree > maxDegree) {
        maxDegree = degree;
        bestNode = candidate;
      }
    }
    return bestNode;
  }

  private checkReachabilityExcluding(start: string, target: string, excludedNode: string): boolean {
    const visited = new Set<string>([start, excludedNode]);
    const queue = [start];
    let head = 0;
    while (head < queue.length) {
      const curr = queue[head++];
      if (curr === target) return true;
      for (const edge of this.adjacency.get(curr) || []) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          if (edge.target === target) return true;
          queue.push(edge.target);
        }
      }
    }
    return false;
  }
}
