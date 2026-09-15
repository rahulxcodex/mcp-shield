/**
 * Persistent Homology Betti-1 (beta_1) Topological Filter
 * (Carriere et al., AISTATS / NeurIPS 2020; Edelsbrunner & Harer)
 * Computes topological invariants over streaming simplicial complexes:
 * - beta_0: Number of connected components (sub-agent partitions)
 * - beta_1: Number of independent 1-dimensional topological cycles (data-flow loops)
 * Benign operations form transient acyclic trees (beta_1 = 0);
 * Multi-tool exfiltration chains produce robust persistent beta_1 holes.
 */
export interface TopologicalSummary {
  beta0: number; // Connected components
  beta1: number; // Topological 1D cycles (holes)
  persistentLoopDetected: boolean;
  activeCycleNodes: string[];
  eulerCharacteristic: number;
}

export class PersistentHomologyEngine {
  private readonly nodes: Set<string> = new Set();
  private readonly edges: Map<string, Set<string>> = new Map();
  private readonly triangles: Set<string> = new Set();

  constructor() {}

  public addNode(nodeId: string): void {
    this.nodes.add(nodeId);
    if (!this.edges.has(nodeId)) {
      this.edges.set(nodeId, new Set());
    }
  }

  public addEdge(u: string, v: string): void {
    if (u === v) return; // Ignore trivial self-loops in 1-simplex
    this.addNode(u);
    this.addNode(v);

    this.edges.get(u)!.add(v);
    this.edges.get(v)!.add(u);

    // Check for 2-simplices (triangles) with common neighbors
    const uNeighbors = this.edges.get(u)!;
    const vNeighbors = this.edges.get(v)!;

    for (const w of uNeighbors) {
      if (w !== v && vNeighbors.has(w)) {
        // Formed triangle (u, v, w)
        const sorted = [u, v, w].sort().join('::');
        this.triangles.add(sorted);
      }
    }
  }

  /**
   * Computes beta_0 and beta_1 via simplicial boundary ranks
   */
  public computeHomology(): TopologicalSummary {
    const V = this.nodes.size;
    if (V === 0) {
      return { beta0: 0, beta1: 0, persistentLoopDetected: false, activeCycleNodes: [], eulerCharacteristic: 0 };
    }

    // 1. Compute connected components (beta_0) via BFS
    const visited = new Set<string>();
    let beta0 = 0;
    const components: string[][] = [];

    for (const node of this.nodes) {
      if (!visited.has(node)) {
        beta0++;
        const comp: string[] = [];
        const queue = [node];
        visited.add(node);

        while (queue.length > 0) {
          const curr = queue.shift()!;
          comp.push(curr);
          for (const neighbor of this.edges.get(curr) || []) {
            if (!visited.has(neighbor)) {
              visited.add(neighbor);
              queue.push(neighbor);
            }
          }
        }
        components.push(comp);
      }
    }

    // 2. Count distinct undirected edges |E|
    let totalEdges = 0;
    for (const [, neighbors] of this.edges) {
      totalEdges += neighbors.size;
    }
    const E = totalEdges / 2;

    // 3. Count 2-simplices (triangles filling cycles) |T|
    const T = this.triangles.size;

    // 4. Fundamental cycle formula: beta_1 = |E| - |V| + beta_0 - |T|
    // When a cycle is not filled by a 2-simplex, it represents a persistent topological hole
    const rawBeta1 = Math.max(0, E - V + beta0 - T);

    // Identify active cycle nodes if beta_1 > 0
    const activeCycleNodes: string[] = [];
    if (rawBeta1 > 0) {
      for (const comp of components) {
        if (comp.length >= 3) {
          activeCycleNodes.push(...comp);
        }
      }
    }

    const eulerCharacteristic = V - E + T;

    return {
      beta0,
      beta1: rawBeta1,
      persistentLoopDetected: rawBeta1 > 0,
      activeCycleNodes,
      eulerCharacteristic
    };
  }

  public reset(): void {
    this.nodes.clear();
    this.edges.clear();
    this.triangles.clear();
  }
}
